# DL-NIDS-Data
## Instructions
---
### Arguments
-d, --directory: (required) The path to the directory containing PCAP or TSV files for analysis.
-a, --analysis: (optional) If included, generates a summary of the analysis results.
-b, --debug: (optional) Enables debug mode, which skips detailed processing for faster testing.
-r, --recursive: (optional) Recursively searches subdirectories for PCAP files.
### Example
To analyze PCAP files in the `/path/to/pcap_directory`, run:

```bash
python pcap.py -d /path/to/pcap_directory
```

To include analysis summary, use:

```bash
python pcap.py -d /path/to/pcap_directory -a
```

### Output
- The script creates an output directory within the specified directory.
- For each PCAP file, a corresponding CSV file (*_feature.csv) containing extracted features will be saved in the output directory. Additionally, a context CSV file (*_context.csv) with contextual data is generated for each PCAP file.
- If the -a option is used, an analysis summary will be generated based on the extracted data.

### Notes
- If no PCAP files are found, the script will attempt to find TSV files in the specified directory.
- If neither PCAP nor TSV files are present, the script will display a message indicating that the directory contains no files.
---
### Feature Updates(For transformer_data)
1. Memory Usage Tracking
The script includes a print_memory_usage function, which tracks and prints memory usage during processing, particularly useful for monitoring large files and optimizing resource usage.

2. PCAP to TSV Conversion (Using TShark)
For .pcap or .pcapng files, the script automatically uses TShark to convert them to .tsv format.
The parsing time is stored in the tsv_time attribute, and logging records the conversion status.
Specific fields to be extracted are predefined in the _FIELDS attribute.
3. Feature Extraction
The extract_features function extracts stream statistics from the .tsv file (e.g., Src_ip, Dst_ip, etc.).
During parsing, intermediate results are saved to a specified CSV file at defined intervals (save_interval), enhancing efficiency for large datasets.
4. Parallel Context Extraction
The script can extract contextual information in parallel using the extract_context_parallel function, which processes each data segment alongside N neighboring rows to provide context.
This feature, powered by ProcessPoolExecutor, is ideal for large-scale data processing, enabling faster context analysis.
5. Recursive Directory Search
With the -r or --recursive option, the script can recursively search all subdirectories in the specified directory, automatically processing .pcap or .tsv files in each subdirectory.
6. Debug Mode
When the -b or --debug option is included, the script enters a debug mode that skips detailed processing steps for faster testing and functionality verification.
---
## Dependencies
This script requires TShark to be installed on your system for packet analysis. TShark is a command-line tool that is part of the Wireshark suite. Follow the instructions below to install TShark based on your operating system:

### Installation Instructions

#### **For Ubuntu/Debian Systems**
Run the following commands to install TShark:

```bash
sudo apt update
sudo apt install tshark
```

During installation, you may be prompted to allow non-superusers to capture packets. Choose **Yes** if you want to allow this functionality.

#### **For macOS**
If you have Homebrew installed, you can use the following command:

```bash
brew install wireshark
```

After installation, you may need to configure permissions to allow non-superusers to capture packets. You can do this by adding your user to the `wireshark` group:

```bash
sudo usermod -aG wireshark your_username
```

Replace `your_username` with your actual username. Log out and back in for the group changes to take effect.

### Verify TShark Installation
After installation, verify that TShark is installed correctly by running:

```bash
tshark -v
```
You should see the version information if TShark is installed correctly.
---




