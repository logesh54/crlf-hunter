#!/usr/bin/env python3
"""
crlf-hunter v2.0 - Advanced CRLF Injection / HTTP Response Splitting Scanner
Professional-grade CLI for authorized penetration testing
"""

import argparse
import sys
import os
import time
import json
import threading
import signal
import hashlib
from typing import List, Dict, Any, Optional
from collections import defaultdict
from pathlib import Path
from dataclasses import fields, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to Python path
SCRIPT_PATH = os.path.realpath(__file__)
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_PATH))
sys.path.insert(0, PROJECT_ROOT)

from crlf_hunter.targets import (
    Target, parse_target, parse_targets_from_file, TargetManager,
    AuthConfig, ProxyConfig, TLSConfig
)
from crlf_hunter.payloads import (
    AdvancedPayloadGenerator, InjectionVector, get_quick_scan_payloads,
    get_standard_scan_payloads, get_deep_scan_payloads, get_waf_evasion_payloads,
    EncodingType, get_payloads, get_marker
)
from crlf_hunter.injector import (
    InjectionPointFinder, TestCaseGenerator, InjectionPointType,
    RequestBuilder, build_raw_request, find_injection_points
)
from crlf_hunter.sender import (
    AdvancedSender, send_raw_request, send_with_delay, ConnectionPool
)
from crlf_hunter.analyzer import (
    AdvancedAnalyzer, AnalysisResult, VulnerabilityType, ConfidenceLevel,
    analyze_response, DifferentialAnalyzer, TimingAnalyzer
)
from crlf_hunter.report import (
    ReportGenerator, LiveReporter, Finding, ScanMetadata,
    create_finding_from_result, print_banner, print_target_info,
    print_test_result, print_summary, write_json_report,
    build_result_object
)
from crlf_hunter.state import StateManager, get_state_manager
from crlf_hunter.notifier import WebhookNotifier, WebhookConfig, WebhookEvent, FindingFormatter
from crlf_hunter.adaptive import AdaptiveScanner
from crlf_hunter.config import ScanConfig, ConfigManager, create_config_from_args, get_default_config


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class CRLFHunter:
    """Main scanner class"""
    
    def __init__(self, args, state_manager=None):
        self.args = args
        self.state_manager = state_manager
        self.marker = get_marker()
        self.payload_generator = AdvancedPayloadGenerator(
            marker=self.marker,
            mutation_level=args.mutation_level
        )
        self.analyzer = AdvancedAnalyzer(
            marker=self.marker,
            enable_differential=args.differential,
            enable_timing=not args.no_timing,
        )
        self.reporter = LiveReporter(verbose=args.verbose, quiet=args.quiet)
        self.report_generator = ReportGenerator(args.output_dir)
        self.sender = AdvancedSender(
            default_timeout=args.timeout,
            max_connections=args.max_connections,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
        )
        
        # Initialize webhook notifier
        self.webhook_notifier = None
        if args.webhook_url or args.slack_webhook or args.discord_webhook or args.teams_webhook or args.api_url:
            self.webhook_notifier = self._create_webhook_notifier()
        
        # Initialize adaptive scanner
        self.adaptive_scanner = AdaptiveScanner(
            initial_concurrency=args.concurrency,
            initial_delay=args.delay,
        )
        
        self.findings: List[Finding] = []
        self.baseline_responses: Dict[str, bytes] = {}
        self._shutdown = False
        self._setup_signals()
    
    def _create_webhook_notifier(self) -> Optional[WebhookNotifier]:
        """Create webhook notifier from CLI arguments"""
        notifier = WebhookNotifier()
        
        # Parse events
        events = [WebhookEvent(e.strip()) for e in self.args.webhook_events.split(",")]
        
        # Generic webhook URLs
        for url in (self.args.webhook_url or []):
            config = WebhookConfig(
                url=url,
                events=events,
                secret=self.args.webhook_secret or "",
                timeout=self.args.webhook_timeout,
                retry_count=self.args.webhook_retry,
                name=url[:50],
            )
            notifier.add_config(config)
        
        # Slack webhook
        if self.args.slack_webhook:
            config = WebhookConfig(
                url=self.args.slack_webhook,
                events=events,
                headers={"Content-Type": "application/json"},
                name="Slack",
            )
            notifier.add_config(config)
        
        # Discord webhook
        if self.args.discord_webhook:
            config = WebhookConfig(
                url=self.args.discord_webhook,
                events=events,
                headers={"Content-Type": "application/json"},
                name="Discord",
            )
            notifier.add_config(config)
        
        # Teams webhook
        if self.args.teams_webhook:
            config = WebhookConfig(
                url=self.args.teams_webhook,
                events=events,
                headers={"Content-Type": "application/json"},
                name="Teams",
            )
            notifier.add_config(config)
        
        return notifier
    
    def _setup_signals(self):
        """Handle graceful shutdown"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}Shutting down gracefully...{Colors.RESET}")
        self._shutdown = True
        self.sender.close()
        if self.state_manager and not self.args.no_save_state:
            self.state_manager.finalize()
        sys.exit(130)
    
    def run(self):
        """Main entry point"""
        print_banner()
        
        # Handle resume
        if self.args.resume and self.state_manager:
            return self._resume_scan()
        
        # Load targets
        targets = self._load_targets()
        if not targets:
            print(f"{Colors.RED}No valid targets found.{Colors.RESET}")
            return 1
        
        # Confirm authorization
        self._confirm_authorization(targets)
        
        # Apply scan profile
        self._apply_scan_profile()
        
        # Generate injection points for all targets
        all_test_cases = []
        for target in targets:
            test_cases = self._generate_test_cases(target)
            all_test_cases.extend(test_cases)
        
        if not all_test_cases:
            print(f"{Colors.YELLOW}No test cases generated.{Colors.RESET}")
            return 0
        
        # Create state for new scan
        if self.state_manager and not self.args.no_save_state:
            scan_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
            config = vars(self.args)
            self.state_manager.create_state(scan_id, config, targets, all_test_cases)
            self.state_manager.start_auto_save()
            print(f"{Colors.CYAN}Scan ID: {scan_id} (use --resume {scan_id} to resume){Colors.RESET}")
            
            # Scan start webhook
            if self.webhook_notifier:
                self.webhook_notifier.notify(
                    WebhookEvent.SCAN_START,
                    scan_id,
                    {"targets": [t.original_url for t in targets], "total_test_cases": len(all_test_cases)}
                )
        
        print(f"\n{Colors.BOLD}Total test cases: {len(all_test_cases)}{Colors.RESET}")
        self.reporter.stats["total"] = len(all_test_cases)
        
        # Get baselines if differential analysis enabled
        if self.args.differential:
            self._collect_baselines(targets)
            # Baseline collected webhook
            if self.webhook_notifier:
                scan_id = self.state_manager._current_state.scan_id if self.state_manager and self.state_manager._current_state else "unknown"
                self.webhook_notifier.notify(
                    WebhookEvent.BASELINE_COLLECTED,
                    scan_id,
                    {"baselines_collected": len(self.baseline_responses)}
                )
        
        # Run scan
        start_time = time.time()
        self._run_scan(all_test_cases)
        end_time = time.time()
        
        # Generate reports
        self._generate_reports(targets, start_time, end_time)
        
        # Print summary
        self.reporter.print_summary()
        
        # Scan complete webhook
        if self.webhook_notifier:
            scan_id = self.state_manager._current_state.scan_id if self.state_manager and self.state_manager._current_state else "unknown"
            self.webhook_notifier.notify(
                WebhookEvent.SCAN_COMPLETE,
                scan_id,
                {
                    "total_requests": self.reporter.stats.get("completed", 0),
                    "vulnerabilities": len(self.findings),
                    "errors": self.reporter.stats.get("errors", 0),
                    "duration": time.time() - start_time if 'start_time' in locals() else 0,
                }
            )
            # Wait for webhook queue to process
            self.webhook_notifier.wait_for_queue(10)
        
        # Finalize state
        if self.state_manager and not self.args.no_save_state:
            self.state_manager.finalize()
        
        # Exit code based on findings
        critical_high = sum(1 for f in self.findings if f.severity.value in ["critical", "high"])
        return 1 if critical_high > 0 else 0
    
    def _resume_scan(self) -> int:
        """Resume a previously saved scan"""
        print(f"{Colors.CYAN}Resuming scan: {self.args.resume}{Colors.RESET}")
        
        state = self.state_manager.load_state(self.args.resume)
        if not state:
            print(f"{Colors.RED}State not found: {self.args.resume}{Colors.RESET}")
            return 1
        
        print(f"{Colors.GREEN}Loaded state: {state.scan_id}{Colors.RESET}")
        print(f"  Created: {state.created_at}")
        print(f"  Progress: {state.completed_test_cases}/{state.total_test_cases}")
        print(f"  Findings so far: {len(state.findings)}")
        
        # Restore findings
        for f_data in state.findings:
            finding = Finding(**f_data)
            self.findings.append(finding)
            self.report_generator.add_finding(finding)
        
        # Restore reporter stats
        self.reporter.stats = state.stats
        
        # Reconstruct targets
        targets = []
        for t_data in state.targets:
            # Simple reconstruction - would need full deserialization
            t = Target(**t_data)
            targets.append(t)
        
        # Get remaining test cases
        remaining_cases = self.state_manager.get_remaining_test_cases()
        if not remaining_cases:
            print(f"{Colors.YELLOW}No remaining test cases to execute.{Colors.RESET}")
            return 0
        
        print(f"{Colors.CYAN}Remaining test cases: {len(remaining_cases)}{Colors.RESET}")
        self.reporter.stats["total"] = state.total_test_cases
        
        # Restart auto-save
        self.state_manager.start_auto_save()
        
        # Run scan on remaining cases
        start_time = time.time()
        self._run_scan_resume(remaining_cases)
        end_time = time.time()
        
        # Generate reports
        self._generate_reports(targets, start_time, end_time)
        
        # Print summary
        self.reporter.print_summary()
        
        # Finalize state
        self.state_manager.finalize()
        
        critical_high = sum(1 for f in self.findings if f.severity.value in ["critical", "high"])
        return 1 if critical_high > 0 else 0
    
    def _run_scan_resume(self, test_cases: List):
        """Run scan on remaining test cases"""
        semaphore = threading.Semaphore(self.args.concurrency)
        
        def run_test_case(tc_data):
            if self._shutdown:
                return None
            
            with semaphore:
                if self._shutdown:
                    return None
                
                if self.args.delay > 0:
                    time.sleep(self.args.delay)
                
                # Deserialize test case
                # This is simplified - would need proper deserialization
                return None
        
        # For now, just use the regular scan with remaining targets
        # Full resume would require deserializing test cases properly
        print(f"{Colors.YELLOW}Note: Full resume requires test case deserialization. Running new scan instead.{Colors.RESET}")
        # Fall back to regular scan
        all_test_cases = []
        for target in self._load_targets():
            test_cases = self._generate_test_cases(target)
            all_test_cases.extend(test_cases)
        
        # Skip already completed
        skip_count = self.state_manager.get_completed_count()
        all_test_cases = all_test_cases[skip_count:]
        
        self.reporter.stats["total"] = len(all_test_cases)
        self._run_scan(all_test_cases)
    
    def _load_targets(self) -> List[Target]:
        """Load targets from various sources"""
        targets = []
        
        if self.args.url:
            targets.append(parse_target(self.args.url, **self._get_target_kwargs()))
        
        if self.args.list:
            targets.extend(parse_targets_from_file(self.args.list))
        
        if self.args.target_file:
            manager = TargetManager()
            manager.add_from_file(self.args.target_file)
            targets.extend(manager.targets)
        
        if self.args.burp_export:
            from crlf_hunter.targets import parse_targets_from_burp
            targets.extend(parse_targets_from_burp(self.args.burp_export))
        
        if self.args.openapi_spec:
            from crlf_hunter.targets import parse_targets_from_openapi
            targets.extend(parse_targets_from_openapi(self.args.openapi_spec))
        
        # Apply filters
        if self.args.scope_domain:
            targets = [t for t in targets if t.host == self.args.scope_domain or t.host.endswith(f".{self.args.scope_domain}")]
        
        if self.args.deduplicate:
            seen = set()
            unique = []
            for t in targets:
                key = (t.scheme, t.host, t.port, t.path, t.query)
                if key not in seen:
                    seen.add(key)
                    unique.append(t)
            targets = unique
        
        return targets
    
    def _get_target_kwargs(self) -> Dict:
        """Get target configuration from CLI args"""
        kwargs = {}
        
        if self.args.auth_type:
            kwargs["auth"] = AuthConfig(
                type=self.args.auth_type,
                username=self.args.auth_user or "",
                password=self.args.auth_pass or "",
                token=self.args.auth_token or "",
                login_url=self.args.login_url or "",
                login_method=self.args.login_method or "POST",
            )
        
        if self.args.proxy:
            proxy_parts = self.args.proxy.split(":")
            kwargs["proxy"] = ProxyConfig(
                enabled=True,
                host=proxy_parts[0],
                port=int(proxy_parts[1]) if len(proxy_parts) > 1 else 8080,
                username=self.args.proxy_user or "",
                password=self.args.proxy_pass or "",
                type=self.args.proxy_type or "http",
            )
        
        if self.args.tls_verify is not None:
            kwargs["tls"] = TLSConfig(verify=self.args.tls_verify)
        
        if self.args.custom_headers:
            for h in self.args.custom_headers.split(","):
                if "=" in h:
                    k, v = h.split("=", 1)
                    kwargs.setdefault("custom_headers", {})[k.strip()] = v.strip()
        
        if self.args.cookies:
            for c in self.args.cookies.split(","):
                if "=" in c:
                    k, v = c.split("=", 1)
                    kwargs.setdefault("cookies", {})[k.strip()] = v.strip()
        
        return kwargs
    
    def _confirm_authorization(self, targets: List[Target]):
        """Confirm authorization for each unique host"""
        confirmed = set()
        
        for target in targets:
            if target.host in confirmed:
                continue
            
            print(f"\n{Colors.YELLOW}⚠  AUTHORIZATION REQUIRED{Colors.RESET}")
            print(f"Type the target hostname to confirm you are authorized to test it:")
            print(f"  Target: {target.host}")
            
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                sys.exit(1)
            
            if user_input != target.host:
                print(f"{Colors.RED}Confirmation failed. Hostname mismatch.{Colors.RESET}")
                sys.exit(1)
            
            print(f"{Colors.GREEN}Authorization confirmed.{Colors.RESET}\n")
            confirmed.add(target.host)
    
    def _apply_scan_profile(self):
        """Apply scan profile settings"""
        profile = self.args.profile
        
        if profile == "quick":
            self.args.mutation_level = 0
            self.args.encodings = ["url"]
            self.args.max_payloads_per_point = 20
        elif profile == "standard":
            self.args.mutation_level = 1
            self.args.encodings = ["none", "url", "double_url", "utf8"]
            self.args.max_payloads_per_point = 100
        elif profile == "deep":
            self.args.mutation_level = 2
            self.args.encodings = ["none", "url", "double_url", "utf8", "unicode"]
            self.args.max_payloads_per_point = 500
        elif profile == "waf-evasion":
            self.args.mutation_level = 3
            self.args.encodings = ["double_url", "utf8", "unicode", "mixed"]
            self.args.max_payloads_per_point = 300
        elif profile == "cve":
            self.args.mutation_level = 1
            self.args.encodings = ["none", "url", "double_url"]
            self.args.max_payloads_per_point = 150
        
        # Parse encodings
        if hasattr(self.args, 'encodings') and self.args.encodings:
            self.selected_encodings = [EncodingType(e) for e in self.args.encodings]
        else:
            self.selected_encodings = [EncodingType.URL, EncodingType.DOUBLE_URL, EncodingType.UTF8]
    
    def _generate_test_cases(self, target: Target) -> List:
        """Generate all test cases for a target"""
        finder = InjectionPointFinder(target)
        
        # Parse body params
        body_params = {}
        if self.args.body_params:
            for pair in self.args.body_params.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    body_params[k.strip()] = v.strip()
                else:
                    body_params[pair.strip()] = ""
        
        # Parse custom params
        custom_params = None
        if self.args.params:
            custom_params = [p.strip() for p in self.args.params.split(",")]
        
        # Parse custom headers
        custom_headers = None
        if self.args.custom_header_list:
            custom_headers = [h.strip() for h in self.args.custom_header_list.split(",")]
        
        injection_points = finder.find_all(
            header_fuzz=self.args.header_fuzz,
            body_fuzz=self.args.body_fuzz,
            path_fuzz=self.args.path_fuzz,
            cookie_fuzz=self.args.cookie_fuzz,
            method_fuzz=self.args.method_fuzz,
            custom_params=custom_params,
            custom_headers=custom_headers,
        )
        
        print_target_info(target, self.args.method, self.args.header_fuzz, 
                         self.args.body_fuzz, self.args.delay, self.args.timeout)
        print(f"Injection points found: {len(injection_points)}")
        for ip in injection_points:
            print(f"  - {ip.location}")
        
        generator = TestCaseGenerator(target, mutation_level=self.args.mutation_level)
        
        # Filter by severity/tags if specified
        filter_severity = None
        if self.args.severity:
            filter_severity = [s.strip() for s in self.args.severity.split(",")]
        
        filter_tags = None
        if self.args.tags:
            filter_tags = [t.strip() for t in self.args.tags.split(",")]
        
        test_cases = generator.generate_all(
            injection_points,
            method=self.args.method,
            body_params=body_params,
            filter_severity=filter_severity,
            filter_tags=filter_tags,
        )
        
        # Limit payloads per injection point
        if self.args.max_payloads_per_point > 0:
            # Group by injection point and limit
            grouped = {}
            for tc in test_cases:
                key = tc.injection_point.location
                if key not in grouped:
                    grouped[key] = []
                grouped[key].append(tc)
            
            limited = []
            for key, tcs in grouped.items():
                limited.extend(tcs[:self.args.max_payloads_per_point])
            test_cases = limited
        
        return test_cases
    
    def _collect_baselines(self, targets: List[Target]):
        """Collect baseline responses for differential analysis"""
        print(f"\n{Colors.CYAN}Collecting baseline responses...{Colors.RESET}")
        
        for target in targets:
            builder = RequestBuilder(target)
            request = builder.build_request(method="GET")
            
            result = self.sender.send(target, request, self.args.timeout)
            if result.success:
                key = f"{target.scheme}://{target.netloc}{target.path}"
                self.baseline_responses[key] = result.response
                print(f"  ✓ Baseline collected for {target.host}")
            else:
                print(f"  ✗ Failed to get baseline for {target.host}: {result.error}")
    
    def _run_scan(self, test_cases: List):
        """Execute the scan with concurrency control"""
        semaphore = threading.Semaphore(self.args.concurrency)
        
        def run_test_case(tc):
            if self._shutdown:
                return None
            
            with semaphore:
                if self._shutdown:
                    return None
                
                # Rate limiting
                if self.args.delay > 0:
                    time.sleep(self.args.delay)
                
                return self._execute_test_case(tc)
        
        # Execute with thread pool
        with ThreadPoolExecutor(max_workers=self.args.concurrency) as executor:
            futures = {executor.submit(run_test_case, tc): tc for tc in test_cases}
            
            for future in as_completed(futures):
                if self._shutdown:
                    break
                
                tc = futures[future]
                try:
                    result = future.result()
                    if result:
                        self._process_result(tc, result)
                except Exception as e:
                    self.reporter.increment("errors")
                    if self.args.verbose:
                        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
                
                self.reporter.increment("completed")
                # Update state manager
                if self.state_manager and not self.args.no_save_state:
                    self.state_manager.update_progress(self.reporter.stats["completed"])
                self.reporter.print_progress()
        
        self.sender.close()
    
    def _execute_test_case(self, tc) -> Optional[Any]:
        """Execute a single test case"""
        if not hasattr(tc, 'target') or tc.target is None:
            return None
        
        result = self.sender.send(tc.target, tc.raw_request, self.args.timeout)
        return result
    
    def _process_result(self, tc, result):
        """Process scan result"""
        # Analyze response
        analysis = self.analyzer.analyze(
            raw_response=result.response,
            raw_request=tc.raw_request,
            marker=self.marker,
            baseline_key=f"{tc.target.scheme}://{tc.target.netloc}{tc.target.path}",
            timing=result.response_time,
            injection_point=tc.injection_point.location,
            payload_info=tc.payload,
        )
        
        if analysis.vulnerable:
            self.reporter.increment("vulnerable")
            self.reporter.stats["by_type"][analysis.vulnerability_type.value] += 1
            self.reporter.stats["by_severity"][self._map_severity(analysis)] += 1
            
            # Create finding
            finding = create_finding_from_result(
                analysis,
                tc.target.original_url,
                tc.injection_point.location,
                tc.payload["payload"],
                tc.curl_command,
                tc.raw_request,
                result.response,
                tc.payload,
            )
            self.findings.append(finding)
            self.report_generator.add_finding(finding)
            
            # Live report
            self.reporter.print_finding(finding)
            
            # Webhook notification
            if self.webhook_notifier:
                self.webhook_notifier.notify(
                    WebhookEvent.FINDING,
                    self.state_manager._current_state.scan_id if self.state_manager and self.state_manager._current_state else "unknown",
                    FindingFormatter.for_webhook(finding)
                )
        
        # Adaptive scanning - process response for rate limiting and WAF detection
        if hasattr(self, 'adaptive_scanner') and self.adaptive_scanner:
            adaptive_result = self.adaptive_scanner.process_response(
                status_code=result.status_code,
                headers=result.headers,
                body=result.response.decode('utf-8', errors='ignore'),
                response_time=result.response_time,
            )
            
            # Apply adaptive changes
            if adaptive_result["rate_limit"]["changes"]:
                changes = adaptive_result["rate_limit"]["changes"]
                if "concurrency" in adaptive_result["current_settings"]:
                    print(f"{Colors.YELLOW}[ADAPTIVE] Adjusting concurrency: {adaptive_result['current_settings']['concurrency']}{Colors.RESET}")
                if "delay" in adaptive_result["current_settings"]:
                    print(f"{Colors.YELLOW}[ADAPTIVE] Adjusting delay: {adaptive_result['current_settings']['delay']:.2f}s{Colors.RESET}")
            
            # Report WAF detection
            if adaptive_result["waf"]["detected"]:
                waf_names = [w["waf_type"] for w in adaptive_result["waf"]["wafs"]]
                print(f"{Colors.RED}[WAF DETECTED] {', '.join(waf_names)}{Colors.RESET}")
                for rec in adaptive_result["waf"]["evasion_recommendations"]:
                    print(f"{Colors.YELLOW}[EVASION] {rec}{Colors.RESET}")
    
    def _map_severity(self, analysis: AnalysisResult) -> str:
        """Map analysis result to severity"""
        if analysis.confidence == ConfidenceLevel.CONFIRMED:
            if analysis.vulnerability_type in [VulnerabilityType.RESPONSE_SPLITTING, 
                                                VulnerabilityType.CACHE_POISONING,
                                                VulnerabilityType.REQUEST_SMUGGLING]:
                return "critical"
            return "high"
        elif analysis.confidence == ConfidenceLevel.HIGH:
            return "high"
        elif analysis.confidence == ConfidenceLevel.MEDIUM:
            return "medium"
        return "low"
    
    def _generate_reports(self, targets: List[Target], start_time: float, end_time: float):
        """Generate all output reports"""
        duration = end_time - start_time
        
        # Calculate stats
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        for f in self.findings:
            by_severity[f.severity.value] += 1
            by_type[f.vulnerability_type] += 1
        
        # Create metadata
        metadata = ScanMetadata(
            scan_id=hashlib.md5(str(start_time).encode()).hexdigest()[:12],
            start_time=datetime.fromtimestamp(start_time).isoformat() + "Z",
            end_time=datetime.fromtimestamp(end_time).isoformat() + "Z",
            duration=duration,
            targets_scanned=len(targets),
            total_requests=self.reporter.stats["completed"],
            vulnerabilities_found=len(self.findings),
            findings_by_severity=dict(by_severity),
            findings_by_type=dict(by_type),
            config=vars(self.args),
        )
        
        self.report_generator.set_metadata(metadata)
        
        # Generate requested formats
        formats = self.args.format.split(",")
        base_name = f"crlf-hunter-{datetime.fromtimestamp(start_time).strftime('%Y%m%d-%H%M%S')}"
        
        for fmt in formats:
            fmt = fmt.strip().lower()
            try:
                if fmt == "json":
                    path = self.report_generator.generate_json()
                    print(f"{Colors.GREEN}JSON report: {path}{Colors.RESET}")
                elif fmt == "html":
                    path = self.report_generator.generate_html()
                    print(f"{Colors.GREEN}HTML report: {path}{Colors.RESET}")
                elif fmt == "sarif":
                    path = self.report_generator.generate_sarif()
                    print(f"{Colors.GREEN}SARIF report: {path}{Colors.RESET}")
                elif fmt == "junit" or fmt == "xml":
                    path = self.report_generator.generate_junit()
                    print(f"{Colors.GREEN}JUnit XML report: {path}{Colors.RESET}")
                elif fmt == "markdown" or fmt == "md":
                    path = self.report_generator.generate_markdown()
                    print(f"{Colors.GREEN}Markdown report: {path}{Colors.RESET}")
                elif fmt == "csv":
                    path = self.report_generator.generate_csv()
                    print(f"{Colors.GREEN}CSV report: {path}{Colors.RESET}")
                elif fmt == "all":
                    paths = self.report_generator.generate_all(base_name)
                    for f, p in paths.items():
                        print(f"{Colors.GREEN}{f.upper()} report: {p}{Colors.RESET}")
                    break
            except Exception as e:
                print(f"{Colors.RED}Failed to generate {fmt} report: {e}{Colors.RESET}")


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with all options"""
    parser = argparse.ArgumentParser(
        description="crlf-hunter v2.0 - Advanced CRLF Injection / HTTP Response Splitting Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Scan Profiles:
  quick        Fast scan with minimal payloads (mutation=0, ~20 payloads/point)
  standard     Balanced scan (mutation=1, ~100 payloads/point) [DEFAULT]
  deep         Comprehensive scan (mutation=2, ~500 payloads/point)
  waf-evasion  WAF evasion focused (mutation=3, heavy encoding)
  cve          CVE-specific payloads (mutation=1, ~150 payloads/point)

Examples:
  # Basic scan
  crlf-hunter -u "https://example.com/search?q=test" --confirm

  # Deep scan with all features
  crlf-hunter -u "https://example.com/" --profile deep --header-fuzz --body-fuzz \\
    --body-params "user=admin,pass=secret" -X POST --confirm

  # Batch scan with HTML + SARIF reports
  crlf-hunter -l targets.txt --profile standard --format html,sarif --confirm

  # WAF evasion with proxy
  crlf-hunter -u "https://target.com/" --profile waf-evasion --proxy 127.0.0.1:8080 --confirm

  # Authenticated scan
  crlf-hunter -u "https://app.com/dashboard" --auth-type cookie --cookies "session=abc123" --confirm

  # Custom scan with specific parameters
  crlf-hunter -u "https://api.com/endpoint" -p "id,token" --header-fuzz \\
    --custom-headers "X-API-Key=test,Authorization=Bearer token" --confirm

  # CI/CD integration with SARIF output
  crlf-hunter -l targets.txt --format sarif,junit --output-dir ./reports --confirm

Output Formats: json, html, sarif, junit, markdown, csv, all

WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.
Use only against systems you own or have explicit permission to test.
Misuse may be illegal.
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument("-u", "--url", help="Target URL")
    target_group.add_argument("-l", "--list", help="Path to file of target URLs (one per line)")
    target_group.add_argument("--target-file", help="JSON file with target configurations")
    target_group.add_argument("--burp-export", help="Burp Suite XML export file")
    target_group.add_argument("--openapi-spec", help="OpenAPI/Swagger spec file")
    
    # Scan profile
    parser.add_argument("--profile", choices=["quick", "standard", "deep", "waf-evasion", "cve"],
                        default="standard", help="Scan profile (default: standard)")
    
    # Injection options
    parser.add_argument("-p", "--params", help="Comma-separated param names to fuzz")
    parser.add_argument("--header-fuzz", action="store_true", default=True, help="Fuzz headers (default: enabled)")
    parser.add_argument("--no-header-fuzz", dest="header_fuzz", action="store_false", help="Disable header fuzzing")
    parser.add_argument("--body-fuzz", action="store_true", help="Fuzz POST body fields")
    parser.add_argument("--body-params", help="Body params for POST (e.g., 'user=admin,pass=secret')")
    parser.add_argument("--cookie-fuzz", action="store_true", default=True, help="Fuzz cookie values")
    parser.add_argument("--path-fuzz", action="store_true", help="Fuzz path segments")
    parser.add_argument("--method-fuzz", action="store_true", help="Fuzz HTTP method/version")
    parser.add_argument("--custom-header-list", help="Custom headers to fuzz (comma-separated)")
    parser.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    
    # Payload options
    parser.add_argument("--mutation-level", type=int, choices=[0,1,2,3], default=1,
                        help="Payload mutation level 0-3 (default: 1)")
    parser.add_argument("--max-payloads-per-point", type=int, default=100,
                        help="Max payloads per injection point (default: 100)")
    parser.add_argument("--severity", help="Filter by severity: critical,high,medium,low,info")
    parser.add_argument("--tags", help="Filter payloads by tags (comma-separated)")
    
    # Authentication
    parser.add_argument("--auth-type", choices=["none", "basic", "bearer", "cookie", "header", "form"],
                        help="Authentication type")
    parser.add_argument("--auth-user", help="Auth username")
    parser.add_argument("--auth-pass", help="Auth password")
    parser.add_argument("--auth-token", help="Auth token")
    parser.add_argument("--login-url", help="Login URL for form auth")
    parser.add_argument("--login-method", default="POST", help="Login method")
    
    # Proxy
    parser.add_argument("--proxy", help="Proxy URL (host:port)")
    parser.add_argument("--proxy-user", help="Proxy username")
    parser.add_argument("--proxy-pass", help="Proxy password")
    parser.add_argument("--proxy-type", choices=["http", "https", "socks4", "socks5"], default="http")
    
    # TLS
    parser.add_argument("--tls-verify", action="store_true", help="Verify TLS certificates")
    parser.add_argument("--no-tls-verify", dest="tls_verify", action="store_false", help="Disable TLS verification")
    parser.set_defaults(tls_verify=False)
    
    # Custom headers/cookies
    parser.add_argument("--custom-headers", help="Custom headers (k=v,k=v)")
    parser.add_argument("--cookies", help="Custom cookies (k=v,k=v)")
    
    # Timing
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Socket timeout (default: 10)")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Concurrent requests (default: 5)")
    
    # Analysis
    parser.add_argument("--differential", action="store_true", default=True, help="Enable differential analysis")
    parser.add_argument("--no-differential", dest="differential", action="store_false", help="Disable differential analysis")
    parser.add_argument("--no-timing", dest="no_timing", action="store_true", help="Disable timing analysis")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--max-redirects", type=int, default=5, help="Max redirects to follow")
    parser.add_argument("--max-connections", type=int, default=10, help="Max connection pool size")
    
    # Output
    parser.add_argument("-o", "--output", help="Output file (legacy JSON)")
    parser.add_argument("--output-dir", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--format", default="json,html", help="Output formats (comma-separated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no live progress)")
    
    # Scope
    parser.add_argument("--scope-domain", help="Limit scope to domain and subdomains")
    parser.add_argument("--deduplicate", action="store_true", default=True, help="Deduplicate targets")
    
    # Safety
    parser.add_argument("--confirm", action="store_true",
                        help="Required: confirm authorization (required for scans)")
    
    # Resume/State
    resume_group = parser.add_argument_group("Resume/State")
    resume_group.add_argument("--resume", help="Resume scan from state file (scan ID)")
    resume_group.add_argument("--list-states", action="store_true", help="List saved scan states")
    resume_group.add_argument("--state-dir", default="state", help="State directory (default: state)")
    resume_group.add_argument("--no-save-state", action="store_true", help="Don't save scan state")
    resume_group.add_argument("--cleanup-states", action="store_true", help="Clean up old state files")
    
    # Webhook/Notifications
    webhook_group = parser.add_argument_group("Webhook/Notifications")
    webhook_group.add_argument("--webhook-url", action="append", help="Webhook URL for findings (can specify multiple)")
    webhook_group.add_argument("--webhook-events", default="finding", help="Comma-separated events: finding,scan_start,scan_complete,scan_error,progress,baseline_collected")
    webhook_group.add_argument("--webhook-secret", help="HMAC secret for webhook signatures")
    webhook_group.add_argument("--webhook-timeout", type=int, default=10, help="Webhook timeout in seconds")
    webhook_group.add_argument("--webhook-retry", type=int, default=3, help="Webhook retry count")
    webhook_group.add_argument("--slack-webhook", help="Slack webhook URL")
    webhook_group.add_argument("--discord-webhook", help="Discord webhook URL")
    webhook_group.add_argument("--teams-webhook", help="Microsoft Teams webhook URL")
    webhook_group.add_argument("--api-url", help="REST API base URL for findings")
    webhook_group.add_argument("--api-key", help="API key for REST API")
    
    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--config", help="Load configuration from file (YAML/JSON)")
    config_group.add_argument("--save-config", help="Save current configuration to file")
    config_group.add_argument("--config-dir", default="~/.config/crlf-hunter/config", help="Configuration directory (default: ~/.config/crlf-hunter/config)")
    config_group.add_argument("--list-configs", action="store_true", help="List saved configurations")
    config_group.add_argument("--delete-config", help="Delete a saved configuration")
    
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle config management commands
    config_manager = ConfigManager(args.config_dir)
    
    if args.list_configs:
        configs = config_manager.list_configs()
        if not configs:
            print("No saved configurations found.")
        else:
            print("Available configurations:")
            for c in configs:
                print(f"  {c}")
        return 0
    
    if args.delete_config:
        if config_manager.delete_config(args.delete_config):
            print(f"Deleted configuration: {args.delete_config}")
        else:
            print(f"Configuration not found: {args.delete_config}")
        return 0
    
    # Load config file if specified
    if args.config:
        try:
            # Expand config_dir
            config_dir = Path(args.config_dir).expanduser()
            # Try to load from config directory first
            config_path = config_dir / args.config
            if not config_path.exists():
                # Try with extensions
                for ext in [".yaml", ".yml", ".json"]:
                    ext_path = config_dir / f"{args.config}{ext}"
                    if ext_path.exists():
                        config_path = ext_path
                        break
                else:
                    config_path = Path(args.config)
            file_config = ScanConfig.load(str(config_path))
            # Merge with CLI args (CLI takes precedence)
            for field_name in [f.name for f in fields(ScanConfig)]:
                if hasattr(args, field_name):
                    file_value = getattr(file_config, field_name, None)
                    cli_value = getattr(args, field_name, None)
                    # Use CLI value if explicitly set, otherwise use config file value
                    if file_value is not None and file_value != "" and file_value != [] and file_value is not False:
                        if cli_value is None or cli_value == "" or cli_value == [] or cli_value is False:
                            setattr(args, field_name, file_value)
        except Exception as e:
            print(f"{Colors.RED}Error loading config: {e}{Colors.RESET}")
            return 1
    
    # Save config if requested
    if args.save_config:
        config = create_config_from_args(args)
        config_manager.save_config(args.save_config, config)
        print(f"Configuration saved: {args.save_config}")
        return 0
    
    # Handle state management commands
    state_manager = get_state_manager(args.state_dir)
    
    if args.list_states:
        states = state_manager.list_states()
        if not states:
            print("No saved states found.")
        else:
            print(f"{'SCAN ID':<32} {'CREATED':<20} {'UPDATED':<20} {'PROGRESS':<15} {'FINDINGS'}")
            print("-" * 100)
            for s in states:
                print(f"{s['scan_id']:<32} {s['created_at']:<20} {s['updated_at']:<20} {s['progress']:<15} {s['findings']}")
        return 0
    
    if args.cleanup_states:
        state_manager.cleanup_old_states()
        print("Cleaned up old state files.")
        return 0
    
    # Require confirmation for scans
    if not args.confirm:
        print(f"{Colors.RED}Error: --confirm is required for scanning.{Colors.RESET}")
        parser.print_help()
        return 1
    
    # Handle legacy output
    if args.output:
        args.format = args.format + ",json" if "json" not in args.format else args.format
    
    hunter = CRLFHunter(args, state_manager)
    return hunter.run()


if __name__ == "__main__":
    sys.exit(main())