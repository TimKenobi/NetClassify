import csv
import socket
import yaml
from concurrent.futures import ThreadPoolExecutor
from dns import resolver as dns_resolver
import requests
import ipaddress
from tqdm import tqdm
import whois
from collections import Counter
import logging
import traceback
import os
import sys
import argparse

# Optional tkinter import for GUI file selection
import platform
if platform.system() == 'Darwin':
    # Completely disable tkinter on macOS due to Tcl/Tk version conflicts
    TKINTER_AVAILABLE = False
    logging.warning("Tkinter disabled on macOS due to version conflicts")
else:
    try:
        import tkinter as tk
        from tkinter import filedialog, ttk
        TKINTER_AVAILABLE = True
        logging.info("Tkinter GUI enabled")
    except ImportError:
        TKINTER_AVAILABLE = False
        logging.warning("Tkinter not available. GUI mode disabled.")

# Optional matplotlib import for chart generation
try:
    # Only import matplotlib if tkinter is available to avoid version conflicts
    if TKINTER_AVAILABLE:
        import matplotlib
        matplotlib.use('TkAgg')  # Use TkAgg backend when tkinter is available
        import matplotlib.pyplot as plt
        MATPLOTLIB_AVAILABLE = True
    else:
        # Disable matplotlib completely when tkinter is not available
        MATPLOTLIB_AVAILABLE = False
        logging.warning("Tkinter not available. Matplotlib disabled to prevent version conflicts.")
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logging.warning("Matplotlib not available. Chart generation will be disabled.")

# Load and validate configuration
try:
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Validate required configuration sections
    required_config_keys = ['logging', 'validation', 'third_party_services', 'defaults']
    for key in required_config_keys:
        if key not in config:
            raise ValueError(f"Missing required config section: {key}")
except Exception as e:
    logging.error(f"Configuration error: {str(e)}")
    raise

# Configure logging from config
logging.basicConfig(
    level=getattr(logging, config['logging']['level']),
    format=config['logging']['format'],
    handlers=[
        logging.FileHandler(config['logging']['file']),
        logging.StreamHandler()
    ]
)

# Initialize configuration-dependent variables
REQUIRED_SECTIONS = set(config['validation']['required_sections'])
found_sections = set()

def read_owned_assets(file_path):
    """Read and parse the OwnedAssets.txt file to extract known IPs and domains.
    
    Args:
        file_path (str): Path to the OwnedAssets.txt file
        
    Returns:
        tuple: (set of owned_ips, set of owned_domains)
        
    Raises:
        ValueError: If required sections are missing from the file
        FileNotFoundError: If the file doesn't exist
        PermissionError: If the file isn't readable
    """
    owned_ips = set()
    owned_domains = set()
    with open(file_path, 'r') as f:
        section = None
        for line in f:
            line = line.strip()
            if line in REQUIRED_SECTIONS:
                found_sections.add(line)
                section = 'ips' if line == 'Known Public IPs' else 'domains'
            elif line == 'KnownParked Domains':
                section = 'domains'  # Treat parked as domains
            elif section == 'ips' and line:
                try:
                    # Assume CIDR or IP, add to set
                    ipaddress.ip_network(line)
                    owned_ips.add(line)
                except ValueError:
                    logging.warning(f"Skipping invalid IP/CIDR: {line}")
            elif section == 'domains' and line:
                owned_domains.add(line)
    # Verify all required sections were found
    missing_sections = REQUIRED_SECTIONS - found_sections
    if missing_sections:
        raise ValueError(f"Owned assets file missing required sections: {', '.join(missing_sections)}")

    return owned_ips, owned_domains

def is_subdomain_match(domain, owned_domains):
    """Check if a domain matches any owned domain pattern, including wildcards.
    
    Args:
        domain (str): Domain to check
        owned_domains (set): Set of owned domains (may include wildcard patterns)
        
    Returns:
        bool: True if domain matches any owned pattern
    """
    domain = domain.lower()
    
    for owned_domain in owned_domains:
        owned_domain = owned_domain.lower()
        
        # Exact match
        if domain == owned_domain:
            return True
            
        # Wildcard subdomain match (*.example.com)
        if owned_domain.startswith('*.'):
            base_domain = owned_domain[2:]  # Remove *.
            if domain.endswith('.' + base_domain) or domain == base_domain:
                return True
                
        # Check if domain is subdomain of owned domain
        if domain.endswith('.' + owned_domain):
            return True
            
        # Check if owned domain is subdomain of domain (reverse check)
        if owned_domain.endswith('.' + domain):
            return True
    
    return False

def check_cloud_provider_ip(ip_str, cloud_providers):
    """Check if an IP belongs to any cloud provider IP ranges.
    
    Args:
        ip_str (str): IP address to check
        cloud_providers (dict): Cloud provider configuration
        
    Returns:
        tuple: (provider_name, is_match) or (None, False)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for provider_key, provider_config in cloud_providers.items():
            if 'ip_ranges' in provider_config:
                for ip_range in provider_config['ip_ranges']:
                    try:
                        if ip in ipaddress.ip_network(ip_range):
                            return provider_config['name'], True
                    except ValueError:
                        continue
    except ValueError:
        pass
    return None, False

def check_asset(value, owned_ips, owned_domains):
    """Analyze an individual asset (IP or domain) against known infrastructure.
    
    Args:
        value (str): The IP or domain to check
        owned_ips (set): Known owned IP ranges
        owned_domains (set): Known owned domains
        
    Returns:
        tuple: (status, details) where:
            - status: 'Approved', 'SAS', 'Review Needed', or 'Deny'
            - details: String with analysis details
    """
    details = ""
    try:
        is_ip = True
        try:
            ipaddress.ip_address(value)
        except ValueError:
            is_ip = False
        
        if is_ip:
            # Reverse DNS for IPs
            try:
                hostname = socket.gethostbyaddr(value)[0]
                details += f"Reverse DNS: {hostname}\n"
                # Check if hostname matches owned domains (including wildcard patterns)
                if is_subdomain_match(hostname, owned_domains):
                    return 'Approved', details
            except socket.herror:
                details += "No reverse DNS record found.\n"
            ip = value  # Use the IP itself
        else:
            # Forward DNS for domains
            answers = dns_resolver.resolve(value, 'A')
            ip = answers[0].to_text()
            details += f"Resolved IP: {ip}\n"
        
        # Check if IP is in owned IPs
        for owned in owned_ips:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(owned):
                return 'Approved', details
        
        # Enhanced cloud provider detection using IP ranges
        cloud_providers = config.get('cloud_providers', {})
        provider_name, is_cloud_ip = check_cloud_provider_ip(ip, cloud_providers)
        if is_cloud_ip:
            details += f"Cloud Provider IP: {provider_name}\n"
        
        # Check if domain matches owned domains (including wildcard patterns)
        if not is_ip and is_subdomain_match(value, owned_domains):
            return 'Approved', details
        
        # Whois lookup for deeper info
        try:
            # Skip whois for known CDN subdomains
            if '.cloudfront.net' in value.lower():
                details += "Whois: CloudFront CDN domain\n"
                return 'SAS', f"Points to AWS CloudFront\n{details}"
            
            # Try whois lookup with error handling
            try:
                w = whois.whois(ip if is_ip else value)
                if hasattr(w, 'domain_name') and w.domain_name is not None:
                    details += f"Whois Org: {getattr(w, 'org', 'N/A')}\nWhois Name: {getattr(w, 'name', 'N/A')}\n"
                else:
                    details += "Whois: No registered domain\n"
            except AttributeError as e:
                # Handle different whois library versions
                details += f"Whois: Library version issue - {str(e)}\n"
            except Exception as whois_error:
                error_msg = str(whois_error)
                # Clean up verbose whois legal text
                if "TERMS OF USE:" in error_msg:
                    error_msg = "Whois lookup restricted for this domain type"
                details += f"Whois: {error_msg}\n"
                
        except Exception as e:
            logging.error(f"Whois lookup failed for {value if not is_ip else ip}: {str(e)}")
            details += f"Whois: {str(e)}\n"
        
        # Enhanced third-party detection from config
        third_party_services = config['third_party_services']
        cloud_providers = config.get('cloud_providers', {})
        lower_details = details.lower()
        lower_value = value.lower()
        
        # Check legacy third_party_services first
        for key, provider in third_party_services.items():
            if key in lower_details or key in lower_value:
                return 'SAS', f"Points to {provider}\n{details}"
        
        # Check enhanced cloud provider keywords
        for provider_key, provider_config in cloud_providers.items():
            provider_name = provider_config['name']
            keywords = provider_config.get('keywords', [])
            
            for keyword in keywords:
                if keyword in lower_details or keyword in lower_value:
                    if is_cloud_ip:  # If we already detected cloud IP, be more confident
                        return 'SAS', f"Confirmed {provider_name} service\n{details}"
                    else:
                        return 'SAS', f"Points to {provider_name}\n{details}"
        
        # Endpoint testing (only for domains)
        if not is_ip:
            try:
                for scheme in ['http', 'https']:
                    response = requests.get(f"{scheme}://{value}", timeout=5)
                    if response.status_code < 400:
                        details += f"{scheme.upper()} Status: {response.status_code}, Content Snippet: {response.text[:100]}\n"
                        return 'Review Needed', details
                    details += f"{scheme.upper()} Status: {response.status_code}\n"
            except requests.RequestException as e:
                logging.error(f"Endpoint test failed for {value}:\n{traceback.format_exc()}")
                details += f"Endpoint unreachable: {str(e)}\n"
        
        return 'Deny', details
    except Exception as e:
        logging.error(f"Error processing asset {value}:\n{traceback.format_exc()}")
        return 'Deny', details + str(e)

def select_csv_file_cli():
    """Command-line file selection when GUI is not available."""
    print("\n📁 CSV File Selection")
    print("=" * 30)
    
    # Look for CSV files in current directory
    csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    
    if csv_files:
        print("Found CSV files in current directory:")
        for i, file in enumerate(csv_files, 1):
            print(f"  {i}. {file}")
        
        while True:
            try:
                choice = input(f"\nSelect file (1-{len(csv_files)}) or enter full path: ").strip()
                
                # Try to parse as number first
                try:
                    file_index = int(choice) - 1
                    if 0 <= file_index < len(csv_files):
                        return csv_files[file_index]
                    else:
                        print(f"Invalid selection. Please choose 1-{len(csv_files)}")
                        continue
                except ValueError:
                    # Not a number, treat as file path
                    if os.path.exists(choice) and choice.endswith('.csv'):
                        return choice
                    else:
                        print("File not found or not a CSV file. Please try again.")
                        continue
                        
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return None
    else:
        # No CSV files found, ask for path
        while True:
            try:
                file_path = input("Enter path to CSV file: ").strip()
                if os.path.exists(file_path) and file_path.endswith('.csv'):
                    return file_path
                else:
                    print("File not found or not a CSV file. Please try again.")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return None

def select_csv_file_gui():
    """GUI file selection when tkinter is available."""
    if not TKINTER_AVAILABLE:
        return select_csv_file_cli()
    
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    csv_path = filedialog.askopenfilename(
        title="Select Asset CSV File", 
        filetypes=[("CSV Files", "*.csv")]
    )
    root.destroy()
    return csv_path if csv_path else None

def generate_results_chart(results):
    """Generate a pie chart visualization of the classification results.
    
    Args:
        results (list): List of result dictionaries from check_asset
        
    Displays:
        matplotlib pie chart showing distribution of status classifications (if available)
    """
    if not MATPLOTLIB_AVAILABLE:
        logging.info("Matplotlib not available. Skipping chart generation.")
        # Print text summary instead
        status_counts = Counter(row['new_status'] for row in results)
        print("\n📊 Asset Classification Summary:")
        print("=" * 40)
        total = sum(status_counts.values())
        for status, count in status_counts.most_common():
            percentage = (count / total) * 100
            print(f"  {status}: {count} ({percentage:.1f}%)")
        print("=" * 40)
        return
    
    status_counts = Counter(row['new_status'] for row in results)
    
    labels = status_counts.keys()
    sizes = status_counts.values()
    
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('Asset Check Results Summary')
    plt.show()

def main(owned_path, output_path, input_csv=None, status_filter='not_reviewed'):
    """Main function to execute the asset checking workflow.
    
    Args:
        owned_path (str): Path to OwnedAssets.txt
        output_path (str): Path for output CSV file
        input_csv (str, optional): Path to input CSV file (if not provided, will prompt for selection)
        status_filter (str, optional): Comma-separated list of status values to process (default: not_reviewed)
        
    Workflow:
        1. Reads owned assets
        2. Selects or prompts for input CSV
        3. Processes all assets
        4. Writes results to output CSV
        5. Generates summary chart
    """
    # Validate input files
    if not os.path.exists(owned_path):
        raise FileNotFoundError(f"Owned assets file not found: {owned_path}")
    if not os.access(owned_path, os.R_OK):
        raise PermissionError(f"Owned assets file not readable: {owned_path}")

    # Validate output file
    output_dir = os.path.dirname(output_path) or '.'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Output directory not writable: {output_dir}")

    owned_ips, owned_domains = read_owned_assets(owned_path)
    results = []
    
    # Select CSV file
    if input_csv and os.path.exists(input_csv):
        csv_path = input_csv
        print(f"📁 Using input file: {csv_path}")
    else:
        print("🔍 Selecting CSV file...")
        if TKINTER_AVAILABLE:
            try:
                csv_path = select_csv_file_gui()
            except Exception as e:
                print(f"⚠️  GUI file selection failed: {e}")
                print("Falling back to command-line selection...")
                csv_path = select_csv_file_cli()
        else:
            csv_path = select_csv_file_cli()
    
    if not csv_path:
        logging.error("No input file selected. Exiting.")
        return
    
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Input CSV file not found: {csv_path}")

    with open(csv_path, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing headers")
            
        # Detect CSV format and normalize to expected format
        fieldnames = [fn.strip() for fn in reader.fieldnames]
        
        # Map common column names to expected 'value' and 'status' columns
        value_column_candidates = ['value', 'Domain Name', 'IP Address', 'domain', 'ip', 'asset']
        status_column_candidates = ['status', 'Rapid7EASMDomain:status', 'Rapid7EASMIpAddress:status']
        
        value_column = None
        status_column = None
        
        # Find the value column
        for candidate in value_column_candidates:
            if candidate in fieldnames:
                value_column = candidate
                break
        
        # Find the status column
        for candidate in status_column_candidates:
            if candidate in fieldnames:
                status_column = candidate
                break
        
        if not value_column:
            raise ValueError(f"CSV missing asset column. Expected one of: {', '.join(value_column_candidates)}\nFound columns: {', '.join(fieldnames)}")
        
        # If no status column found, create one with default value
        if not status_column:
            logging.warning("No status column found in CSV. Using default 'not_reviewed' for all assets.")
            status_column = 'status'

        original_fieldnames = list(reader.fieldnames)
        
        # Parse status filter (comma-separated values)
        raw_rows = list(reader)
        
        # Normalize rows to have 'value' and 'status' keys
        normalized_rows = []
        for row in raw_rows:
            normalized_row = dict(row)  # Copy all original fields
            normalized_row['value'] = row.get(value_column, '').strip()
            normalized_row['status'] = row.get(status_column, 'not_reviewed').strip()
            normalized_rows.append(normalized_row)
        
        # Apply status filter
        if status_filter.lower() == 'all':
            rows = normalized_rows
        else:
            status_values = [s.strip().lower().replace(' ', '_') for s in status_filter.split(',')]
            rows = [row for row in normalized_rows if row.get('status', '').strip().lower().replace(' ', '_') in status_values]
    
    logging.info(f"Found {len(rows)} assets to review.")
    
    # Get max workers from config or use default
    max_workers = config.get('performance', {}).get('max_threads', 10)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create list of tuples containing (row, future)
        future_to_row = []
        for row in rows:
            value = row.get('value')
            if value:
                future = executor.submit(
                    check_asset,
                    value,
                    owned_ips,
                    owned_domains
                )
                future_to_row.append((row, future))
        
        # Process results as they complete, preserving order
        results = []
        for row, future in tqdm(
            future_to_row,
            total=len(future_to_row),
            desc="Processing Assets",
            unit="asset"
        ):
            try:
                result, details = future.result()
                results.append({
                    **row,
                    'new_status': result,
                    'details': details,
                    'best_guess': result
                })
            except Exception as e:
                logging.error(f"Error processing asset {row.get('value')}: {str(e)}")
                results.append({
                    **row,
                    'new_status': 'Error',
                    'details': str(e),
                    'best_guess': 'Error'
                })
    
    # Write output to new CSV
    with open(output_path, 'w', newline='', encoding='utf-8') as outfile:
        # Define fieldnames, adding the new ones
        fieldnames = original_fieldnames + ['new_status', 'details', 'best_guess']
        # Filter out potential duplicate new fields if they were somehow in the original
        fieldnames = sorted(set(fieldnames), key=fieldnames.index)
        
        writer = csv.DictWriter(outfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)
    
    logging.info(f"Processing complete. Results exported to {output_path}")

    # Generate and display the results chart
    if results:
        logging.info("Generating results summary chart...")
        generate_results_chart(results)
    
    # Map fields for web GUI compatibility
    for result in results:
        # Map 'value' to appropriate web GUI fields
        if 'value' in result:
            result['asset'] = result['value']  # Primary asset identifier
            if result.get('type') == 'domain':
                result['domain'] = result['value']
            elif result.get('type') == 'ip_address':
                result['ip'] = result['value']
                result['ip_address'] = result['value']  # For web GUI compatibility
    
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Enhanced Asset Classification Tool for Penetration Testing Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Interactive mode with file selection
  %(prog)s --input assets.csv                 # Specify input CSV file
  %(prog)s --input assets.csv --output results.csv  # Specify both input and output
  %(prog)s --owned MyAssets.txt --input test.csv    # Custom owned assets file
  %(prog)s --input assets.csv --web-gui       # Launch web-based GUI with results
        """
    )
    
    parser.add_argument(
        '--input', '-i',
        help='Path to input CSV file (if not provided, will prompt for selection)',
        default=None
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Path to output CSV file (default: asset_check_results.csv)',
        default='asset_check_results.csv'
    )
    
    parser.add_argument(
        '--owned', '-a',
        help='Path to owned assets file (default: OwnedAssets.txt)',
        default='OwnedAssets.txt'
    )
    
    parser.add_argument(
        '--no-gui',
        action='store_true',
        help='Force command-line mode (disable GUI file selection)'
    )
    
    parser.add_argument(
        '--web-gui',
        action='store_true',
        help='Launch web-based GUI after processing (requires Flask)'
    )
    
    parser.add_argument(
        '--status-filter',
        help='Comma-separated list of status values to process (default: not_reviewed)',
        default='not_reviewed'
    )
    
    args = parser.parse_args()
    
    # Disable GUI if requested
    if args.no_gui:
        import sys
        current_module = sys.modules[__name__]
        current_module.TKINTER_AVAILABLE = False
        logging.info("GUI mode disabled by --no-gui flag")
    
    try:
        print("🌐 NetClassify - Network Asset Classification Tool")
        print(f"📊 11+ Cloud Providers • 25+ SaaS Services • IPv4/IPv6 Support")
        print(f"💻 Platform: macOS compatible (GUI: {'✅' if TKINTER_AVAILABLE else '❌'}, Charts: {'✅' if MATPLOTLIB_AVAILABLE else '❌'})")
        print("=" * 60)
        
        results = main(args.owned, args.output, args.input, args.status_filter)
        
        print("\n✅ Asset classification completed successfully!")
        
        # Launch web GUI if requested
        if args.web_gui:
            print("\n🌐 Launching web-based GUI...")
            try:
                import web_gui
                import threading
                import time
                
                # Start Flask server in background first
                flask_thread = threading.Thread(target=lambda: web_gui.app.run(debug=False, host='127.0.0.1', port=5001, use_reloader=False))
                flask_thread.daemon = True
                flask_thread.start()
                
                # Wait for Flask to start
                print("⏳ Starting web server...")
                time.sleep(3)
                
                # Send results to web GUI
                import requests
                try:
                    response = requests.post('http://127.0.0.1:5001/api/results', 
                                           json={'results': results}, 
                                           timeout=5)
                    if response.status_code == 200:
                        print("📊 Results loaded in web GUI")
                    else:
                        print(f"⚠️  Could not load results in web GUI (status: {response.status_code})")
                except requests.RequestException as e:
                    print(f"⚠️  Could not connect to web GUI: {e}")
                
                print("🎨 Web GUI available at: http://127.0.0.1:5001")
                print("💡 Features: Sorting, Dark/Light mode, Real-time search")
                print("🔄 Press Ctrl+C to stop the web server")
                
                # Keep the main thread alive
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Web GUI server stopped")
                    
            except ImportError:
                print("❌ Flask not installed. Install with: pip install flask")
            except Exception as e:
                print(f"❌ Error launching web GUI: {e}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)