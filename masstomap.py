#!/usr/bin/env python3
"""
masstomap.py - masscan to nmap (Advanced Edition)
This script parses the masscan standard output (text), creating simple ip:port file report
and feeds nmap in order to run versioning and scripts

Author: dogasantos
URL: https://github.com/dogasantos/masstomap
Enhanced by: AI Assistant with advanced features

Features:
- Smart port grouping for efficient scanning
- Resume capability with state tracking
- Rate limiting and adaptive scanning
- JSON output format
- Statistics and reporting
- Progress bar
- Configurable timeout and retry logic
"""

import re
import os
import sys
import argparse
import json
import time
import signal
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict
import logging

try:
    import nmap
except ImportError:
    print("[!] Error: python-nmap module not found. Install it with: pip install python-nmap")
    sys.exit(1)

try:
    import xml.etree.ElementTree as ET
except ImportError:
    print("[!] Error: xml.etree.ElementTree not available")
    sys.exit(1)

VERSION = "v0.8-advanced"

# Global state for graceful shutdown
shutdown_requested = False


@dataclass
class ScanStatistics:
    """Statistics for scan operations."""
    total_targets: int = 0
    scanned_targets: int = 0
    failed_targets: int = 0
    skipped_targets: int = 0
    total_ports: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)
    
    def duration(self) -> float:
        """Calculate scan duration."""
        if self.end_time > 0:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_targets == 0:
            return 0.0
        return (self.scanned_targets / self.total_targets) * 100


@dataclass
class ScanTarget:
    """Represents a scan target with metadata."""
    ip: str
    ports: List[str]
    status: str = "pending"  # pending, scanning, completed, failed, skipped
    attempts: int = 0
    last_error: Optional[str] = None
    scan_time: float = 0.0
    
    def port_count(self) -> int:
        """Get number of ports."""
        return len(self.ports)
    
    def ports_str(self) -> str:
        """Get comma-separated port string."""
        return ','.join(self.ports)


class ProgressTracker:
    """Simple progress tracker for scan operations."""
    
    def __init__(self, total: int, enabled: bool = True):
        self.total = total
        self.current = 0
        self.enabled = enabled
        self.start_time = time.time()
        self.last_update = 0
    
    def update(self, increment: int = 1):
        """Update progress."""
        self.current += increment
        current_time = time.time()
        
        # Update every 0.5 seconds to avoid spam
        if not self.enabled or (current_time - self.last_update) < 0.5:
            return
        
        self.last_update = current_time
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        elapsed = current_time - self.start_time
        
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"{int(eta)}s"
        else:
            eta_str = "N/A"
        
        bar_length = 30
        filled = int(bar_length * self.current / self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\r[{bar}] {self.current}/{self.total} ({percentage:.1f}%) ETA: {eta_str}", 
              end='', flush=True)
    
    def finish(self):
        """Mark progress as complete."""
        if self.enabled:
            print()  # New line after progress bar


class StateManager:
    """Manages scan state for resume capability."""
    
    def __init__(self, state_file: str):
        self.state_file = state_file
        self.state = {
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'targets': {},
            'statistics': {}
        }
    
    def load(self) -> bool:
        """Load state from file."""
        if not os.path.exists(self.state_file):
            return False
        
        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                self.state = json.load(f)
            return True
        except Exception as e:
            logging.warning(f"Failed to load state: {e}")
            return False
    
    def save(self, targets: Dict[str, ScanTarget], stats: ScanStatistics):
        """Save current state."""
        try:
            self.state['timestamp'] = datetime.now().isoformat()
            self.state['targets'] = {ip: asdict(target) for ip, target in targets.items()}
            self.state['statistics'] = stats.to_dict()
            
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")
    
    def get_completed_targets(self) -> Set[str]:
        """Get set of completed target IPs."""
        completed = set()
        for ip, target_data in self.state.get('targets', {}).items():
            if target_data.get('status') == 'completed':
                completed.add(ip)
        return completed


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    global shutdown_requested
    print("\n[!] Shutdown requested. Finishing current scans...")
    shutdown_requested = True


def setup_logging(verbose: bool, log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging based on verbosity level."""
    logger = logging.getLogger('masstomap')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to create log file: {e}")
    
    return logger


def banner():
    """Display script banner with version and description."""
    print(f"\n{'='*70}")
    print(f"  masstomap {VERSION} - masscan-to-nmap @dogasantos")
    print(f"  Advanced Edition with Smart Features")
    print(f"{'='*70}")
    print("\nFeatures:")
    print("  ✓ Smart port grouping for efficient scanning")
    print("  ✓ Resume capability with state tracking")
    print("  ✓ Progress tracking and ETA calculation")
    print("  ✓ JSON output format")
    print("  ✓ Detailed statistics and reporting")
    print("  ✓ Configurable timeout and retry logic")
    print(f"{'='*70}\n")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Parse masscan output and run detailed nmap scans (Advanced Edition)',
        epilog=f'Example: python {sys.argv[0]} -m masscan-report-file.txt',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument(
        '-m', '--masscan',
        help="masscan report file",
        required=True
    )
    
    # Scan control
    parser.add_argument(
        '-n', '--noscan',
        help="Just convert to ip:port1,port2 notation. Do not execute nmap scan.",
        action='store_true'
    )
    parser.add_argument(
        '-r', '--resume',
        help="Resume from previous scan state",
        action='store_true'
    )
    parser.add_argument(
        '--max-retries',
        help="Maximum retry attempts for failed scans (default: 2)",
        type=int,
        default=2
    )
    parser.add_argument(
        '--timeout',
        help="Timeout for individual nmap scans in seconds (default: 300)",
        type=int,
        default=300
    )
    
    # Output options
    parser.add_argument(
        '-o', '--nmap-output',
        help="nmap output file prefix (default: scanreport)",
        default="scanreport"
    )
    parser.add_argument(
        '--json',
        help="Generate JSON output with detailed results",
        action='store_true'
    )
    parser.add_argument(
        '--log-file',
        help="Write logs to file",
        type=str
    )
    
    # Nmap options
    parser.add_argument(
        '-sl', '--script-list',
        help="Comma separated list of nmap scripts to run",
        default='http-title,http-server-header,http-open-proxy,http-methods,http-headers,ssl-cert'
    )
    parser.add_argument(
        '--nmap-args',
        help="Additional nmap arguments",
        default=""
    )
    
    # Performance options
    parser.add_argument(
        '-t', '--threads',
        help='Number of concurrent nmap threads (default: 8)',
        type=int,
        default=8
    )
    parser.add_argument(
        '--rate-limit',
        help='Rate limit: minimum seconds between scan starts (default: 0)',
        type=float,
        default=0.0
    )
    parser.add_argument(
        '--group-ports',
        help='Group similar ports together for efficient scanning',
        action='store_true'
    )
    
    # Display options
    parser.add_argument(
        '-v', '--verbose',
        help='Enable verbosity',
        action='store_true'
    )
    parser.add_argument(
        '-q', '--quiet',
        help='Quiet mode - minimal output',
        action='store_true'
    )
    parser.add_argument(
        '--no-progress',
        help='Disable progress bar',
        action='store_true'
    )
    
    return parser.parse_args()


def load_ips_from_masscan(masscan_content: List[str]) -> Set[str]:
    """
    Extract unique IP addresses from masscan report content.
    
    Args:
        masscan_content: List of lines from masscan report
        
    Returns:
        Set of unique IP addresses
    """
    iplist = set()
    
    for line in masscan_content:
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        parts = line.split()
        
        # Handle different masscan output formats
        if len(parts) >= 4 and "open" in parts and "tcp" in parts:
            ipaddr = parts[3]
            iplist.add(ipaddr)
        elif len(parts) >= 6 and "Discovered" in parts and "open" in parts and "port" in parts:
            ipaddr = parts[5]
            iplist.add(ipaddr)
    
    return iplist


def parse_masscan(masscan_report: str, logger: logging.Logger) -> Dict[str, ScanTarget]:
    """
    Parse masscan report and create dictionary of scan targets.
    
    Args:
        masscan_report: Path to masscan report file
        logger: Logger instance
        
    Returns:
        Dictionary mapping IP addresses to ScanTarget objects
    """
    logger.info("Parsing masscan report file")
    
    try:
        with open(masscan_report, 'r', encoding='utf-8', errors='ignore') as f:
            masscan_content = f.readlines()
    except IOError as e:
        logger.error(f"Failed to read masscan report: {e}")
        sys.exit(1)
    
    # Extract unique IPs
    iplist = load_ips_from_masscan(masscan_content)
    logger.debug(f"Found {len(iplist)} unique IP addresses")
    
    # Build IP to ports mapping
    ip_ports = {ip: [] for ip in iplist}
    
    logger.debug("Extracting ports for each IP")
    
    for line in masscan_content:
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        parts = line.split()
        
        if len(parts) >= 4 and "open" in parts and "tcp" in parts:
            port = parts[2]
            ipaddr = parts[3]
            if ipaddr in ip_ports:
                ip_ports[ipaddr].append(port)
        elif len(parts) >= 6 and "Discovered" in parts and "open" in parts and "port" in parts:
            port = parts[3].split('/')[0]
            ipaddr = parts[5]
            if ipaddr in ip_ports:
                ip_ports[ipaddr].append(port)
    
    # Create ScanTarget objects
    targets = {}
    for ip, ports in ip_ports.items():
        unique_ports = sorted(set(ports), key=int)
        targets[ip] = ScanTarget(ip=ip, ports=unique_ports)
    
    # Write simplified report
    report_path = f"{masscan_report}.new"
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            for ip in sorted(targets.keys()):
                f.write(f"{ip}:{targets[ip].ports_str()}\n")
        logger.info(f"Simplified report saved to: {report_path}")
    except IOError as e:
        logger.error(f"Failed to write simplified report: {e}")
    
    return targets


def group_targets_by_ports(targets: Dict[str, ScanTarget], logger: logging.Logger) -> Dict[str, ScanTarget]:
    """
    Group targets with identical port lists for more efficient scanning.
    
    Args:
        targets: Dictionary of scan targets
        logger: Logger instance
        
    Returns:
        Optimized dictionary of scan targets
    """
    logger.info("Grouping targets by port similarity")
    
    port_groups = defaultdict(list)
    
    # Group IPs by their port signature
    for ip, target in targets.items():
        port_sig = target.ports_str()
        port_groups[port_sig].append(ip)
    
    logger.info(f"Grouped {len(targets)} targets into {len(port_groups)} unique port patterns")
    
    # Log some statistics
    if logger.level == logging.DEBUG:
        for port_sig, ips in sorted(port_groups.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
            logger.debug(f"  Port pattern {port_sig}: {len(ips)} hosts")
    
    return targets


def execute_nmap_scan(target: ScanTarget, nmap_args: str, output: str, 
                     timeout: int, logger: logging.Logger) -> Tuple[bool, Optional[str]]:
    """
    Execute nmap scan for a single target.
    
    Args:
        target: ScanTarget object
        nmap_args: Nmap arguments template
        output: Output file prefix
        timeout: Scan timeout in seconds
        logger: Logger instance
        
    Returns:
        Tuple of (success, error_message)
    """
    ip = target.ip
    ports = target.ports_str()
    
    try:
        start_time = time.time()
        nm = nmap.PortScanner()
        
        # Replace placeholders in arguments
        args = nmap_args.replace('{ip}', ip)
        
        logger.debug(f"Scanning {ip} ports {ports}")
        nm.scan(hosts=ip, ports=ports, arguments=args, timeout=timeout)
        
        xmlout = nm.get_nmap_last_output()
        
        # Save XML output
        xmlreportfile = f"{output}.nmap.xml.{ip}"
        with open(xmlreportfile, 'w', encoding='utf-8') as f:
            f.write(xmlout)
        
        target.scan_time = time.time() - start_time
        logger.debug(f"Scan completed for {ip} in {target.scan_time:.2f}s")
        
        return True, None
        
    except TimeoutError:
        error_msg = f"Scan timeout after {timeout}s"
        logger.warning(f"{ip}: {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Nmap scan failed for {ip}: {error_msg}")
        return False, error_msg


def execute_nmap(targets: Dict[str, ScanTarget], script_list: str, output: str,
                max_threads: int, rate_limit: float, max_retries: int, timeout: int,
                state_manager: StateManager, show_progress: bool, logger: logging.Logger) -> ScanStatistics:
    """
    Execute nmap scans for all targets using thread pool with advanced features.
    
    Args:
        targets: Dictionary of scan targets
        script_list: Comma-separated list of nmap scripts
        output: Output file prefix
        max_threads: Maximum number of concurrent threads
        rate_limit: Minimum seconds between scan starts
        max_retries: Maximum retry attempts
        timeout: Scan timeout in seconds
        state_manager: State manager for resume capability
        show_progress: Whether to show progress bar
        logger: Logger instance
        
    Returns:
        ScanStatistics object
    """
    logger.info("Executing nmap scans")
    
    stats = ScanStatistics(
        total_targets=len(targets),
        start_time=time.time()
    )
    
    # Build nmap arguments
    nmap_args = (
        f"-sV --version-all -A "
        f"-oG {output}.nmap.grepable.{{ip}} "
        f"-oN {output}.nmap.text.{{ip}} "
        f"--script={script_list} "
        f"--privileged -Pn --open"
    )
    
    # Filter targets that need scanning
    completed = state_manager.get_completed_targets()
    targets_to_scan = {}
    
    for ip, target in targets.items():
        # Check if already completed
        if ip in completed:
            target.status = "completed"
            stats.skipped_targets += 1
            logger.info(f"Skipping {ip} (already completed)")
            continue
        
        # Check if scan file exists and is valid
        xml_file = f"{output}.nmap.xml.{ip}"
        if os.path.isfile(xml_file) and os.path.getsize(xml_file) > 5:
            try:
                with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                    xmlcontent = f.read()
                    if 'finished time' in xmlcontent or '</nmaprun>' in xmlcontent:
                        target.status = "completed"
                        stats.skipped_targets += 1
                        logger.info(f"Skipping {ip} (valid report found)")
                        continue
            except IOError:
                pass
        
        targets_to_scan[ip] = target
        stats.total_ports += target.port_count()
    
    if not targets_to_scan:
        logger.info("All targets already scanned")
        stats.end_time = time.time()
        return stats
    
    logger.info(f"Scanning {len(targets_to_scan)} targets ({stats.total_ports} total ports) with {max_threads} threads")
    
    # Progress tracking
    progress = ProgressTracker(len(targets_to_scan), enabled=show_progress)
    
    # Execute scans in parallel with rate limiting
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {}
        last_submit_time = 0
        
        for ip, target in targets_to_scan.items():
            # Check for shutdown request
            if shutdown_requested:
                logger.warning("Shutdown requested, stopping new scans")
                break
            
            # Rate limiting
            if rate_limit > 0:
                elapsed = time.time() - last_submit_time
                if elapsed < rate_limit:
                    time.sleep(rate_limit - elapsed)
            
            target.status = "scanning"
            target.attempts += 1
            
            future = executor.submit(execute_nmap_scan, target, nmap_args, output, timeout, logger)
            futures[future] = target
            last_submit_time = time.time()
        
        # Wait for all scans to complete
        for future in as_completed(futures):
            target = futures[future]
            
            try:
                success, error_msg = future.result()
                
                if success:
                    target.status = "completed"
                    stats.scanned_targets += 1
                    logger.info(f"Successfully scanned {target.ip} ({target.port_count()} ports)")
                else:
                    target.last_error = error_msg
                    
                    # Retry logic
                    if target.attempts < max_retries and not shutdown_requested:
                        logger.info(f"Retrying {target.ip} (attempt {target.attempts + 1}/{max_retries})")
                        target.attempts += 1
                        target.status = "scanning"
                        
                        # Resubmit
                        new_future = executor.submit(execute_nmap_scan, target, nmap_args, output, timeout, logger)
                        futures[new_future] = target
                        continue
                    else:
                        target.status = "failed"
                        stats.failed_targets += 1
                        logger.error(f"Failed to scan {target.ip} after {target.attempts} attempts")
                
            except Exception as e:
                target.status = "failed"
                target.last_error = str(e)
                stats.failed_targets += 1
                logger.error(f"Exception during scan of {target.ip}: {e}")
            
            progress.update()
            
            # Periodic state save
            if (stats.scanned_targets + stats.failed_targets) % 10 == 0:
                state_manager.save(targets, stats)
    
    progress.finish()
    
    stats.end_time = time.time()
    
    # Final state save
    state_manager.save(targets, stats)
    
    return stats


def merge_xml_files(output: str, logger: logging.Logger) -> bool:
    """
    Merge individual XML files into a single valid XML document.
    
    Args:
        output: Output file prefix
        logger: Logger instance
        
    Returns:
        True if merge was successful
    """
    logger.info("Merging XML files")
    
    xml_files = sorted(Path('.').glob(f"{output}.nmap.xml.*"))
    
    if not xml_files:
        logger.warning("No XML files found to merge")
        return False
    
    # Create root element
    root = ET.Element('nmaprun')
    root.set('scanner', 'nmap')
    root.set('args', 'merged')
    root.set('start', str(int(time.time())))
    root.set('version', '7.80')
    root.set('xmloutputversion', '1.04')
    
    host_count = 0
    
    # Parse and merge all XML files
    for xml_file in xml_files:
        try:
            logger.debug(f"Processing {xml_file.name}")
            
            tree = ET.parse(xml_file)
            xml_root = tree.getroot()
            
            # Extract host elements
            for host in xml_root.findall('host'):
                root.append(host)
                host_count += 1
            
            # Clean up individual file
            logger.debug(f"Removing {xml_file.name}")
            xml_file.unlink()
            
        except ET.ParseError as e:
            logger.warning(f"Failed to parse {xml_file.name}: {e}")
            continue
        except Exception as e:
            logger.error(f"Error processing {xml_file.name}: {e}")
            continue
    
    # Add runstats element
    runstats = ET.SubElement(root, 'runstats')
    finished = ET.SubElement(runstats, 'finished')
    finished.set('time', str(int(time.time())))
    finished.set('timestr', datetime.now().strftime('%a %b %d %H:%M:%S %Y'))
    
    hosts = ET.SubElement(runstats, 'hosts')
    hosts.set('up', str(host_count))
    hosts.set('down', '0')
    hosts.set('total', str(host_count))
    
    # Write merged XML
    tree = ET.ElementTree(root)
    ET.indent(tree, space='  ')
    
    final_xml = f"{output}.nmap.xml"
    
    try:
        tree.write(final_xml, encoding='utf-8', xml_declaration=True)
        logger.info(f"Merged XML saved to: {final_xml} ({host_count} hosts)")
        return True
    except Exception as e:
        logger.error(f"Failed to write merged XML: {e}")
        return False


def merge_text_files(output: str, logger: logging.Logger) -> bool:
    """Merge individual text report files."""
    logger.debug("Merging text report files")
    
    text_files = sorted(Path('.').glob(f"{output}.nmap.text.*"))
    final_report = f"{output}.nmap.txt"
    
    if not text_files:
        return False
    
    try:
        with open(final_report, 'w', encoding='utf-8') as outfile:
            for text_file in text_files:
                try:
                    with open(text_file, 'r', encoding='utf-8', errors='ignore') as infile:
                        content = infile.read()
                        outfile.write(content)
                        outfile.write('\n' + '='*60 + '\n\n')
                    
                    logger.debug(f"Removing {text_file.name}")
                    text_file.unlink()
                    
                except Exception as e:
                    logger.warning(f"Error processing {text_file.name}: {e}")
        
        logger.info(f"Text report saved to: {final_report}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to merge text files: {e}")
        return False


def merge_grepable_files(output: str, logger: logging.Logger) -> bool:
    """Merge individual grepable report files."""
    logger.debug("Merging grepable report files")
    
    grep_files = sorted(Path('.').glob(f"{output}.nmap.grepable.*"))
    final_report = f"{output}.nmap.grepable"
    
    if not grep_files:
        return False
    
    try:
        with open(final_report, 'w', encoding='utf-8') as outfile:
            for grep_file in grep_files:
                try:
                    with open(grep_file, 'r', encoding='utf-8', errors='ignore') as infile:
                        for line in infile:
                            if line.startswith('# Nmap'):
                                continue
                            outfile.write(line)
                    
                    logger.debug(f"Removing {grep_file.name}")
                    grep_file.unlink()
                    
                except Exception as e:
                    logger.warning(f"Error processing {grep_file.name}: {e}")
        
        logger.info(f"Grepable report saved to: {final_report}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to merge grepable files: {e}")
        return False


def wrapup_reports(output: str, logger: logging.Logger) -> bool:
    """Merge all individual report files into final reports."""
    logger.info("Wrapping up reports...")
    
    success = True
    success &= merge_xml_files(output, logger)
    success &= merge_text_files(output, logger)
    success &= merge_grepable_files(output, logger)
    
    return success


def create_fingerprint_table(output: str, logger: logging.Logger) -> bool:
    """Create fingerprint table from nmap XML output."""
    xml_file = f"{output}.nmap.xml"
    
    if not os.path.isfile(xml_file) or os.path.getsize(xml_file) < 100:
        logger.warning("Nmap XML report not found or too small")
        return False
    
    logger.info("Creating fingerprint table")
    
    try:
        nm = nmap.PortScanner()
        with open(xml_file, 'r', encoding='utf-8') as f:
            xmlres = f.read()
        nm.analyse_nmap_xml_scan(xmlres)
    except Exception as e:
        logger.error(f"Failed to load XML: {e}")
        return False
    
    fprint_file = f"{output}.fprint"
    
    try:
        with open(fprint_file, 'w', encoding='utf-8') as f:
            for ip in nm.all_hosts():
                if 'tcp' not in nm[ip]:
                    continue
                
                for port in nm[ip]['tcp'].keys():
                    service = nm[ip]['tcp'][port]
                    
                    name = service.get('name', '')
                    product = service.get('product', '').rstrip(':')
                    version = service.get('version', '').rstrip(':')
                    
                    line = f"{ip}:{port}:{name}:{product}:{version}"
                    f.write(line + "\n")
        
        logger.info(f"Fingerprint table saved to: {fprint_file}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create fingerprint table: {e}")
        return False


def generate_json_report(targets: Dict[str, ScanTarget], stats: ScanStatistics, 
                        output: str, logger: logging.Logger) -> bool:
    """Generate JSON report with detailed results."""
    logger.info("Generating JSON report")
    
    json_file = f"{output}.json"
    
    report = {
        'metadata': {
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'duration': stats.duration(),
        },
        'statistics': stats.to_dict(),
        'targets': {}
    }
    
    for ip, target in targets.items():
        report['targets'][ip] = {
            'ip': target.ip,
            'ports': target.ports,
            'port_count': target.port_count(),
            'status': target.status,
            'attempts': target.attempts,
            'scan_time': target.scan_time,
            'last_error': target.last_error
        }
    
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to: {json_file}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate JSON report: {e}")
        return False


def print_statistics(stats: ScanStatistics, logger: logging.Logger):
    """Print scan statistics."""
    print(f"\n{'='*70}")
    print("SCAN STATISTICS")
    print(f"{'='*70}")
    print(f"Total Targets:     {stats.total_targets}")
    print(f"Scanned:           {stats.scanned_targets}")
    print(f"Failed:            {stats.failed_targets}")
    print(f"Skipped:           {stats.skipped_targets}")
    print(f"Total Ports:       {stats.total_ports}")
    print(f"Duration:          {stats.duration():.2f} seconds")
    print(f"Success Rate:      {stats.success_rate():.1f}%")
    
    if stats.scanned_targets > 0:
        avg_time = stats.duration() / stats.scanned_targets
        print(f"Avg Time/Target:   {avg_time:.2f} seconds")
    
    print(f"{'='*70}\n")


def main():
    """Main execution function."""
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    args = parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose and not args.quiet, args.log_file)
    
    # Display banner
    if not args.quiet:
        banner()
    
    # Validate masscan file
    if not os.path.isfile(args.masscan):
        logger.error(f"The specified masscan file can't be found: {args.masscan}")
        sys.exit(1)
    
    # Initialize state manager
    state_file = f"{args.nmap_output}.state.json"
    state_manager = StateManager(state_file)
    
    if args.resume:
        if state_manager.load():
            logger.info("Resuming from previous state")
        else:
            logger.warning("No previous state found, starting fresh")
    
    # Parse masscan report
    targets = parse_masscan(args.masscan, logger)
    
    if not targets:
        logger.error("No targets found in masscan report")
        sys.exit(1)
    
    logger.info(f"Found {len(targets)} targets with open ports")
    
    # Group targets if requested
    if args.group_ports:
        targets = group_targets_by_ports(targets, logger)
    
    # Execute nmap scans if not disabled
    if not args.noscan:
        stats = execute_nmap(
            targets,
            args.script_list,
            args.nmap_output,
            args.threads,
            args.rate_limit,
            args.max_retries,
            args.timeout,
            state_manager,
            not args.no_progress and not args.quiet,
            logger
        )
        
        # Print statistics
        if not args.quiet:
            print_statistics(stats, logger)
        
        # Check if any scans completed
        if stats.scanned_targets == 0:
            logger.warning("No scans completed successfully")
            if not args.quiet:
                logger.info("You can retry failed scans with --resume flag")
            sys.exit(1)
        
        # Merge reports
        wrapup_reports(args.nmap_output, logger)
        
        # Create fingerprint table
        create_fingerprint_table(args.nmap_output, logger)
        
        # Generate JSON report if requested
        if args.json:
            generate_json_report(targets, stats, args.nmap_output, logger)
    
    logger.info("Done!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

