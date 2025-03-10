import pikepdf
import itertools
import time
import sys
import os
import json
import argparse
import multiprocessing
from tqdm import tqdm


def attempt_password(pdf_path, password):
    """Try a single password on the PDF"""
    try:
        with pikepdf.open(pdf_path, password=password) as pdf:
            return True
    except pikepdf.PasswordError:
        return False
    except Exception as e:
        print(f"Error trying password {password}: {str(e)}")
        return False


def worker_process(pdf_path, start_num, count, length, result_queue, progress_queue):
    """Worker process that tries a batch of passwords"""
    for i in range(count):
        current = start_num + i
        password = str(current).zfill(length)

        # Update progress frequently
        if i % 100 == 0 or i == count - 1:
            progress_queue.put(100 if i % 100 == 0 else i % 100)

        # Try the password
        if attempt_password(pdf_path, password):
            result_queue.put(password)
            return

    # Signal completion of batch with no success
    result_queue.put(None)


def get_state_filename(pdf_path):
    """Generate a state filename based on the PDF path"""
    pdf_name = os.path.basename(pdf_path)
    return f"pdf_cracker_state_{pdf_name}.json"


def save_state(pdf_path, current_length, current_number, passwords_tried, start_time):
    """Save the current state to a file"""
    state = {
        "pdf_path": pdf_path,
        "current_length": current_length,
        "current_number": current_number,
        "passwords_tried": passwords_tried,
        "elapsed_time": time.time() - start_time,
        "timestamp": time.time()
    }

    state_file = get_state_filename(pdf_path)
    with open(state_file, "w") as f:
        json.dump(state, f)


def load_state(pdf_path):
    """Load the saved state if it exists"""
    state_file = get_state_filename(pdf_path)
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                state = json.load(f)

            # Verify the state is for the correct PDF
            if state.get("pdf_path") == pdf_path:
                return state
        except Exception as e:
            print(f"Error loading state file: {str(e)}")

    return None


def crack_pdf(pdf_path, exact_digits=None, min_digits=3, max_digits=6, processes=None, ignore_state=False):
    """Try numeric combinations to crack the PDF password with state saving"""
    if not os.path.exists(pdf_path):
        print(f"Error: File '{pdf_path}' not found!")
        return

    print(f"Attempting to crack password for: {pdf_path}")

    # Quick check if PDF is actually password protected
    try:
        with pikepdf.open(pdf_path) as pdf:
            print("This PDF is not password protected!")
            return
    except pikepdf.PasswordError:
        print("PDF is password protected. Starting to crack...")
    except Exception as e:
        print(f"Error opening PDF: {str(e)}")
        return

    # Determine number of processes to use
    if processes is None:
        processes = max(1, multiprocessing.cpu_count() - 1)

    print(f"Using {processes} CPU cores")

    # Check for saved state
    resume_state = None if ignore_state else load_state(pdf_path)

    if resume_state and not ignore_state:
        print(f"Found saved state from {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(resume_state['timestamp']))}")
        print(
            f"Resuming from {resume_state['current_length']}-digit passwords, position {resume_state['current_number']:,}")
        print(
            f"Already tried {resume_state['passwords_tried']:,} passwords over {resume_state['elapsed_time']:.2f} seconds")

        # Use the saved state to determine where to start
        start_time = time.time() - resume_state['elapsed_time']
        total_passwords_tried = resume_state['passwords_tried']
        resume_length = resume_state['current_length']
        resume_position = resume_state['current_number']
    else:
        start_time = time.time()
        total_passwords_tried = 0
        resume_length = None
        resume_position = 0

    # Determine which lengths to try
    if exact_digits is not None:
        length_range = [exact_digits]
        print(f"Testing only {exact_digits}-digit passwords")
    else:
        length_range = range(min_digits, max_digits + 1)
        print(f"Testing numeric passwords from {min_digits} to {max_digits} digits")

    # Skip lengths we've completed if resuming
    if resume_length is not None:
        length_range = [l for l in length_range if l >= resume_length]

    # Try each password length
    for length in length_range:
        total_passwords = 10 ** length

        # If resuming from this length, start from the saved position
        if length == resume_length and resume_position > 0:
            current_start = resume_position
            print(
                f"\nResuming {length}-digit passwords from position {current_start:,} ({current_start / total_passwords * 100:.2f}% complete)")
        else:
            current_start = 0
            print(f"\nTrying {length}-digit passwords ({total_passwords:,} combinations)...")

        # Create a progress bar starting from the saved position
        pbar = tqdm(total=total_passwords, initial=current_start, unit="pw")

        # Keep track of passwords tried for this length
        passwords_tried = 0

        # Use a smaller batch size for better progress updates
        batch_size = 10000

        # For very small password spaces, use an even smaller batch
        if total_passwords < 100000:
            batch_size = min(1000, total_passwords // (processes * 2))

        # Make sure we have at least one batch per process
        batch_size = min(batch_size, total_passwords // processes)

        if batch_size == 0:
            batch_size = 1

        print(f"Using batch size of {batch_size:,} passwords per process")

        # Create queues for results and progress updates
        result_queue = multiprocessing.Queue()
        progress_queue = multiprocessing.Queue()

        # Track active processes
        active_processes = []
        current_number = current_start
        found_password = None

        # Calculate time for last state save
        last_save_time = time.time()

        # Start initial batch of processes
        for _ in range(min(processes, (total_passwords - current_start + batch_size - 1) // batch_size)):
            if current_number >= total_passwords:
                break

            # Calculate how many passwords this batch will try
            this_batch_size = min(batch_size, total_passwords - current_number)

            # Start a new process for this batch
            p = multiprocessing.Process(
                target=worker_process,
                args=(pdf_path, current_number, this_batch_size, length, result_queue, progress_queue)
            )
            p.start()
            active_processes.append(p)
            current_number += this_batch_size

        # Process until we find the password or exhaust all possibilities
        while active_processes and found_password is None:
            # Check for results (non-blocking)
            try:
                result = result_queue.get(block=False)
                if result is not None:
                    found_password = result
                    break
                # A process finished with no success, remove it from active
                finished_processes = [p for p in active_processes if not p.is_alive()]
                for p in finished_processes:
                    active_processes.remove(p)

                # Start new processes if we have more passwords to try
                while current_number < total_passwords and len(active_processes) < processes:
                    this_batch_size = min(batch_size, total_passwords - current_number)
                    p = multiprocessing.Process(
                        target=worker_process,
                        args=(pdf_path, current_number, this_batch_size, length, result_queue, progress_queue)
                    )
                    p.start()
                    active_processes.append(p)
                    current_number += this_batch_size
            except multiprocessing.queues.Empty:
                pass

            # Update progress (non-blocking)
            progress_received = 0
            try:
                while True:
                    progress = progress_queue.get(block=False)
                    progress_received += progress
            except multiprocessing.queues.Empty:
                pass

            # Update the progress bar
            if progress_received > 0:
                passwords_tried += progress_received
                total_passwords_tried += progress_received
                pbar.update(progress_received)

                # Calculate and display speed
                elapsed = time.time() - start_time
                if elapsed > 0:
                    speed = total_passwords_tried / elapsed
                    if speed > 1_000_000:
                        speed_str = f"{speed / 1_000_000:.2f}M/s"
                    elif speed > 1_000:
                        speed_str = f"{speed / 1_000:.2f}K/s"
                    else:
                        speed_str = f"{speed:.2f}/s"

                    # Calculate ETA
                    if speed > 0:
                        eta_seconds = (total_passwords - pbar.n) / speed
                        hours, remainder = divmod(eta_seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        eta_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                    else:
                        eta_str = "unknown"

                    pbar.set_description(
                        f"Tried: {total_passwords_tried:,} | Speed: {speed_str} | ETA: {eta_str}"
                    )

            # Save state periodically (every 5 seconds)
            if time.time() - last_save_time > 5:
                save_state(pdf_path, length, current_number, total_passwords_tried, start_time)
                last_save_time = time.time()

            # Short sleep to prevent CPU thrashing
            time.sleep(0.01)

        # Clean up any remaining processes
        for p in active_processes:
            p.terminate()
            p.join()

        pbar.close()

        # Save final state for this digit length if not found
        if not found_password:
            save_state(pdf_path, length + 1, 0, total_passwords_tried, start_time)

        if found_password:
            print(f"\n\nPASSWORD FOUND: {found_password}")
            print(f"Time taken: {time.time() - start_time:.2f} seconds")
            print(f"Passwords tried: {total_passwords_tried:,}")

            # Save the password to a file
            with open("found_password.txt", "w") as f:
                f.write(f"PDF: {pdf_path}\nPassword: {found_password}")

            # Remove state file since we found the password
            state_file = get_state_filename(pdf_path)
            if os.path.exists(state_file):
                os.remove(state_file)

            return found_password

    print("\nPassword not found after trying all combinations!")
    print(f"Total time spent: {time.time() - start_time:.2f} seconds")
    print(f"Total passwords tried: {total_passwords_tried:,}")

    return None


def main():
    parser = argparse.ArgumentParser(description="High-Performance PDF Password Cracker for numeric passwords")
    parser.add_argument("pdf_file", help="Path to the password-protected PDF file")
    parser.add_argument("-d", "--digits", type=int, help="Exact number of digits to try")
    parser.add_argument("-min", "--min-digits", type=int, default=3,
                        help="Minimum number of digits to try (default: 3)")
    parser.add_argument("-max", "--max-digits", type=int, default=6,
                        help="Maximum number of digits to try (default: 6)")
    parser.add_argument("-p", "--processes", type=int, help="Number of processes to use (default: CPU count - 1)")
    parser.add_argument("--ignore-state", action="store_true", help="Ignore saved state and start fresh")

    args = parser.parse_args()

    try:
        crack_pdf(
            args.pdf_file,
            exact_digits=args.digits,
            min_digits=args.min_digits,
            max_digits=args.max_digits,
            processes=args.processes,
            ignore_state=args.ignore_state
        )
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. State saved - you can resume later.")
    except Exception as e:
        print(f"\nError: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage examples:")
        print("  To try a specific digit length: python pdf_password_cracker.py document.pdf -d 4")
        print("  To try a range of digits: python pdf_password_cracker.py document.pdf -min 3 -max 6")
        print("  To control CPU usage: python pdf_password_cracker.py document.pdf -d 4 -p 2")
        print("  To ignore saved state and start fresh: python pdf_password_cracker.py document.pdf --ignore-state")
        print("  For more options: python pdf_password_cracker.py -h")
        sys.exit(1)

    main()