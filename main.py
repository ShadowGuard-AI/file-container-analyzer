import argparse
import logging
import zipfile
import pathlib
import os
import sys
import mimetypes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    parser = argparse.ArgumentParser(description="Identifies and extracts embedded files from container formats (ZIP, JAR, OLE).")
    parser.add_argument("filepath", help="Path to the container file.")
    parser.add_argument("-o", "--output", help="Output directory for extracted files (default: current directory).", default=".")
    parser.add_argument("-l", "--list", action="store_true", help="List embedded files without extracting.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser.parse_args()

def _sanitized_parts(name):
    parts = []
    for part in pathlib.PurePosixPath(name.replace('\\', '/')).parts:
        if part in ('/', '', '.', '..'):
            continue
        parts.append(part)
    return parts

def _target_for(output_dir, entry_name):
    parts = _sanitized_parts(entry_name)
    if not parts:
        return None
    return pathlib.Path(output_dir).joinpath(*parts)

def extract_zip(filepath, output_dir, list_only):
    """Extracts files from a ZIP/JAR archive. Returns (ok, entry_count)."""
    try:
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            logging.info(f"Processing ZIP archive: {filepath}")
            infos = [i for i in zip_ref.infolist() if not i.filename.endswith('/')]
            if not list_only:
                container_resolved = pathlib.Path(filepath).resolve()
                for file_info in infos:
                    target = _target_for(output_dir, file_info.filename)
                    if target is not None and target.resolve() == container_resolved:
                        logging.error(f"Extraction target for {file_info.filename} resolves to the container itself; refusing the run.")
                        print("Error: an entry would extract onto the container file itself; refusing the run before writing anything.")
                        return (False, 0)
            count = 0
            for file_info in infos:
                filename = file_info.filename
                file_size = file_info.file_size
                file_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                logging.info(f"Found embedded file: {filename}, Size: {file_size}, Type: {file_type}")
                count += 1
                if list_only:
                    continue
                target = _target_for(output_dir, filename)
                if target is None:
                    continue
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zip_ref.open(file_info) as source:
                        data = source.read()
                    with open(target, 'wb') as out:
                        out.write(data)
                    logging.info(f"Extracted {filename} to {target}")
                except Exception as e:
                    logging.error(f"Error extracting {filename}: {e}")
                    return (False, count)
            return (True, count)
    except zipfile.BadZipFile:
        logging.error(f"File {filepath} is not a valid ZIP archive.")
        return (False, 0)
    except Exception as e:
        logging.error(f"An error occurred while processing {filepath}: {e}")
        return (False, 0)

def extract_ole(filepath, output_dir, list_only):
    """Extracts files from an OLE file. olefile is imported here, only on this path."""
    try:
        import olefile
    except ImportError:
        logging.error("The olefile package is required for OLE files; it is not installed.")
        print("Error: the olefile package is required for OLE files and is not installed.")
        return (False, 0)
    try:
        if not olefile.isOleFile(filepath):
            logging.error(f"File {filepath} is not a valid OLE file.")
            return (False, 0)
        ole = olefile.OleFileIO(filepath)
        logging.info(f"Processing OLE file: {filepath}")
        streams = ['/'.join(s) for s in ole.listdir() if s]
        if not list_only:
            container_resolved = pathlib.Path(filepath).resolve()
            for full_stream_path in streams:
                target = _target_for(output_dir, full_stream_path)
                if target is not None and target.resolve() == container_resolved:
                    logging.error("An extraction target resolves to the container itself; refusing the run.")
                    print("Error: an entry would extract onto the container file itself; refusing the run before writing anything.")
                    ole.close()
                    return (False, 0)
        count = 0
        for full_stream_path in streams:
            try:
                stream_data = ole.openstream(full_stream_path).read()
                stream_size = len(stream_data)
                file_type = mimetypes.guess_type(full_stream_path)[0] or "application/octet-stream"
                logging.info(f"Found embedded stream: {full_stream_path}, Size: {stream_size}, Type: {file_type}")
                count += 1
                if list_only:
                    continue
                target = _target_for(output_dir, full_stream_path)
                if target is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with open(target, 'wb') as f:
                    f.write(stream_data)
                logging.info(f"Extracted {full_stream_path} to {target}")
            except Exception as e:
                logging.error(f"Error extracting stream {full_stream_path}: {e}")
                ole.close()
                return (False, count)
        ole.close()
        return (True, count)
    except Exception as e:
        logging.error(f"An error occurred while processing {filepath}: {e}")
        return (False, 0)

def main():
    args = setup_argparse()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")
    filepath = args.filepath
    output_dir = args.output
    list_only = args.list
    if not pathlib.Path(filepath).exists():
        logging.error(f"File not found: {filepath}")
        print(f"Error: container not found: {filepath}")
        return 1
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(filepath):
        ok, count = extract_zip(filepath, output_dir, list_only)
    else:
        # OLE path only: olefile is imported lazily inside this branch.
        try:
            import olefile
            is_ole = olefile.isOleFile(filepath)
        except ImportError:
            is_ole = False
            # A non-ZIP file may be OLE; without olefile it cannot be analyzed here.
            with open(filepath, 'rb') as f:
                header = f.read(8)
            if header == bytes.fromhex('D0CF11E0A1B11AE1'):
                logging.error("OLE container needs the olefile package, which is not installed.")
                print("Error: OLE container needs the olefile package, which is not installed.")
                return 1
        if is_ole:
            ok, count = extract_ole(filepath, output_dir, list_only)
        else:
            logging.error(f"Unsupported container format: {filepath}")
            print(f"Error: unsupported container: {filepath}")
            return 1
    if not ok:
        return 1
    if count == 0:
        print("Error: container is empty; nothing was analyzed.")
        logging.error("Container is empty; nothing was analyzed.")
        return 1
    logging.info(f"Container analysis completed: {count} embedded file(s) found.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
