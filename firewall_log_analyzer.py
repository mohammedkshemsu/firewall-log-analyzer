import re  # Regular expressions module for pattern matching
import pandas as pd  # Pandas module for structured data analysis


def parse_log_line(line):
    """
    Function to parse a single firewall log line and extract key details.

    Args:
    - line (str): A single line from the firewall log file.

    Returns:
    - dict: A dictionary of parsed details (if the line matches the expected pattern).
    - None: If the line does not match the expected pattern.
    """
    # Define the log pattern using regular expressions
    log_pattern = (
        r"SRC=(?P<src_ip>\S+) "  # Match and capture Source IP
        r"DST=(?P<dst_ip>\S+) "  # Match and capture Destination IP
        r"PROTO=(?P<protocol>\S+) "  # Match and capture Protocol (e.g., TCP, UDP)
        r"SPT=(?P<src_port>\d+) "  # Match and capture Source Port (integer)
        r"DPT=(?P<dst_port>\d+) "  # Match and capture Destination Port (integer)
        r"ACTION=(?P<action>\S+)"  # Match and capture Action (e.g., ALLOWED, BLOCKED)
    )

    # Try to match the current log line with the defined pattern
    match = re.search(log_pattern, line.strip())  # Remove unnecessary whitespace
    if match:
        # If a match is found, return a dictionary of the captured fields
        print(f"Matched Line: {line.strip()}")  # Debugging: Print the matched line
        return match.groupdict()  # Convert named groups to a dictionary
    else:
        # If no match is found, log the skipped line for debugging
        print(f"Skipped Line: {line.strip()}")
    return None  # Return None for lines that don't match


def analyze_logs(log_file_path):
    """
    Reads a firewall log file, parses each line, and returns structured data.

    Args:
    - log_file_path (str): Path to the firewall log file.

    Returns:
    - pd.DataFrame: A Pandas DataFrame containing parsed log data.
    - None: If no valid log entries are found or the file is not accessible.
    """
    parsed_data = []  # Initialize an empty list to store parsed log entries
    try:
        # Open the log file in read mode
        with open(log_file_path, "r") as file:
            for line in file:
                # Parse each line in the log file
                parsed_line = parse_log_line(line)
                if parsed_line:  # If the line is valid and parsed successfully
                    parsed_data.append(parsed_line)  # Add parsed data to the list
    except FileNotFoundError:  # Handle the case where the log file is missing
        print("Error: Log file not found.")  # Inform the user about the missing file
        return None

    # If parsed data exists, convert it to a Pandas DataFrame
    if parsed_data:
        df = pd.DataFrame(parsed_data)  # Create a structured DataFrame
        return df  # Return the structured data
    else:
        print("No valid log entries were parsed.")  # Inform the user if no valid logs
        return None


def main():
    """
    Main function to coordinate the log file analysis and display results.
    """
    log_file = "firewall_logs.txt"  # Define the path to the log file
    print(f"Analyzing logs from {log_file}...")  # Inform the user about the process

    # Call the function to analyze logs
    log_data = analyze_logs(log_file)

    if log_data is not None and not log_data.empty:  # Check if valid data exists
        print("\n--- Parsed Firewall Logs ---\n")
        print(log_data)  # Display the full parsed data

        # Filter the parsed logs for entries where action is "BLOCKED"
        blocked_traffic = log_data[log_data["action"] == "BLOCKED"]
        print("\n--- Blocked Traffic ---\n")
        print(blocked_traffic)  # Display only the blocked traffic
    else:
        print("No valid log data found.")  # Inform the user if no valid data exists


# Entry point of the script
if __name__ == "__main__":
    main()
