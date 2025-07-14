import argparse
import logging
import zipfile
import olefile
import pathlib
import os
import io
import mimetypes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the command-line argument parser."""
    parser = argparse.ArgumentParser(description="Identifies and extracts embedded files from container formats (ZIP, JAR, OLE).")
    parser.add_argument("filepath", help="Path to the container file.")
    parser.add_argument("-o", "--output", help="Output directory for extracted files (default: current directory).", default=".")
    parser.add_argument("-l", "--list", action="store_true", help="List embedded files without extracting.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser.parse_args()

def extract_zip(filepath, output_dir, list_only):
    """Extracts files from a ZIP/JAR archive."""
    try:
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            logging.info(f"Processing ZIP archive: {filepath}")
            for file_info in zip_ref.infolist():
                filename = file_info.filename
                file_size = file_info.file_size
                file_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

                logging.info(f"Found embedded file: {filename}, Size: {file_size}, Type: {file_type}")
                
                if list_only:
                    continue

                # Sanitize filename to prevent path traversal vulnerabilities
                safe_filename = os.path.basename(filename)
                output_path = os.path.join(output_dir, safe_filename)

                try:
                    with zip_ref.open(file_info) as source, open(output_path, 'wb') as target:
                        target.write(source.read())
                    logging.info(f"Extracted {filename} to {output_path}")
                except Exception as e:
                     logging.error(f"Error extracting {filename}: {e}")

    except zipfile.BadZipFile:
        logging.error(f"File {filepath} is not a valid ZIP archive.")
        return False
    except Exception as e:
        logging.error(f"An error occurred while processing {filepath}: {e}")
        return False
    return True


def extract_ole(filepath, output_dir, list_only):
    """Extracts files from an OLE (Compound File Binary Format) file."""
    try:
        if not olefile.isOleFile(filepath):
            logging.error(f"File {filepath} is not a valid OLE file.")
            return False

        ole = olefile.OleFileIO(filepath)
        logging.info(f"Processing OLE file: {filepath}")

        for stream_name in ole.listdir():
            if stream_name:
                full_stream_path = '/'.join(stream_name)
                try:
                    stream_data = ole.openstream(full_stream_path).read()
                    stream_size = len(stream_data)
                    file_type = mimetypes.guess_type(full_stream_path)[0] or "application/octet-stream"
                    logging.info(f"Found embedded stream: {full_stream_path}, Size: {stream_size}, Type: {file_type}")

                    if list_only:
                        continue

                    # Sanitize filename
                    safe_filename = os.path.basename(full_stream_path.replace('/', '_'))  # Replace slashes with underscores
                    output_path = os.path.join(output_dir, safe_filename)
                    
                    with open(output_path, 'wb') as f:
                        f.write(stream_data)
                    logging.info(f"Extracted {full_stream_path} to {output_path}")
                    
                except Exception as e:
                    logging.error(f"Error extracting stream {full_stream_path}: {e}")
        ole.close() # Close the olefile to release resources
    except Exception as e:
        logging.error(f"An error occurred while processing {filepath}: {e}")
        return False
    return True


def main():
    """Main function to parse arguments and call appropriate extraction functions."""
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    filepath = args.filepath
    output_dir = args.output
    list_only = args.list

    # Validate file path
    if not pathlib.Path(filepath).exists():
        logging.error(f"File not found: {filepath}")
        return

    # Validate output directory
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Determine file type and call appropriate extraction function
    if zipfile.is_zipfile(filepath):
        extract_zip(filepath, output_dir, list_only)
    elif olefile.isOleFile(filepath):
        extract_ole(filepath, output_dir, list_only)
    else:
        logging.warning(f"Unsupported file format: {filepath}.  Attempting to identify contents.")

        try:
          with open(filepath, 'rb') as f:
              file_header = f.read(4)

          if file_header == b'PK\x03\x04':
              logging.info("Detected ZIP file header. Attempting ZIP extraction.")
              extract_zip(filepath, output_dir, list_only)
          else:
              logging.error(f"Could not identify file type for: {filepath}")
        except Exception as e:
            logging.error(f"Error while probing file type: {e}")


if __name__ == "__main__":
    main()

# Example Usage:
# 1. Run: python file_container_analyzer.py test.zip
#    - Extracts all files from test.zip to the current directory.

# 2. Run: python file_container_analyzer.py test.ole -o output_dir
#    - Extracts all streams from test.ole to the directory 'output_dir'.

# 3. Run: python file_container_analyzer.py test.jar -l
#    - Lists all files embedded in test.jar without extracting them.

# 4. Run: python file_container_analyzer.py test.zip -v
#    - Extracts all files from test.zip and provides verbose output.