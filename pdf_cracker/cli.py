#!/usr/bin/env python3
"""
Command-line interface for the PDF Password Cracker.
"""

import argparse
import os
import sys
import time
from typing import List, Optional
import multiprocessing

from pdf_cracker.core.cracker import PDFCracker
from pdf_cracker.core.generator import (
    NumericPasswordGenerator,
    AlphabeticPasswordGenerator,
    AlphanumericPasswordGenerator,
    DictionaryPasswordGenerator,
    SmartPasswordGenerator,
)
from pdf_cracker.utils.config import Config, verbosity_to_level
from pdf_cracker.utils.logger import Logger
from pdf_cracker.utils.exceptions import PDFCrackerError


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Advanced PDF Password Cracker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Main parameters
    parser.add_argument("pdf_file", help="Path to the password-protected PDF file")

    # Generator options
    generator_group = parser.add_argument_group("Password Generator Options")
    generator_group.add_argument(
        "-t",
        "--types",
        nargs="+",
        choices=["numeric", "alphabetic", "alphanumeric", "dictionary", "smart"],
        default=["smart", "numeric"],
        help="Types of passwords to try",
    )
    generator_group.add_argument(
        "-d", "--digits", type=int, help="Exact number of digits/characters to try"
    )
    generator_group.add_argument(
        "-min",
        "--min-digits",
        type=int,
        default=3,
        help="Minimum number of digits/characters to try",
    )
    generator_group.add_argument(
        "-max",
        "--max-digits",
        type=int,
        default=6,
        help="Maximum number of digits/characters to try",
    )
    generator_group.add_argument(
        "--dictionary", help="Path to dictionary file for dictionary-based attack"
    )
    generator_group.add_argument(
        "--lowercase",
        action="store_true",
        help="Include lowercase letters in alphabetic/alphanumeric passwords",
    )
    generator_group.add_argument(
        "--uppercase",
        action="store_true",
        help="Include uppercase letters in alphabetic/alphanumeric passwords",
    )
    generator_group.add_argument(
        "--symbols",
        action="store_true",
        help="Include symbols in alphanumeric passwords",
    )

    # Performance options
    performance_group = parser.add_argument_group("Performance Options")
    performance_group.add_argument(
        "-p",
        "--processes",
        type=int,
        help="Number of processes to use (default: CPU count - 1)",
    )
    performance_group.add_argument(
        "-b", "--batch-size", type=int, help="Batch size for each worker process"
    )
    performance_group.add_argument(
        "-s",
        "--save-interval",
        type=float,
        default=5.0,
        help="Interval in seconds between saving state",
    )

    # State management
    state_group = parser.add_argument_group("State Management")
    state_group.add_argument(
        "--ignore-state", action="store_true", help="Ignore saved state and start fresh"
    )
    state_group.add_argument("--state-dir", help="Directory to store state files")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-v",
        "--verbosity",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Logging verbosity level",
    )
    output_group.add_argument("--log-file", help="Save log output to this file")
    output_group.add_argument("--output-file", help="Save found password to this file")
    output_group.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress standard output messages"
    )

    # Config management
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--config", help="Path to configuration file")
    config_group.add_argument(
        "--save-config",
        action="store_true",
        help="Save current settings as default configuration",
    )

    return parser


def setup_logger(args, config: Config) -> Logger:
    """Set up logging based on command-line arguments and config"""
    # Command-line args override config
    verbosity = (
        args.verbosity
        if hasattr(args, "verbosity")
        else config.get("verbosity", "info")
    )
    log_file = args.log_file if hasattr(args, "log_file") else config.get("log_file")
    quiet = args.quiet if hasattr(args, "quiet") else False

    # Set up logger
    logger = Logger(
        name="pdf_cracker",
        log_file=log_file,
        level=verbosity_to_level(verbosity),
        console=not quiet,
    )

    return logger


def print_system_info(logger) -> None:
    """Print system information useful for debugging"""
    import platform
    import pikepdf

    logger.info("=== System Information ===")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"CPU count: {multiprocessing.cpu_count()}")
    logger.info(f"pikepdf version: {pikepdf.__version__}")
    logger.info("=========================")


def save_config_from_args(args, config: Config) -> None:
    """Save configuration from command-line arguments"""
    # Update configuration with arguments
    if hasattr(args, "processes") and args.processes:
        config.set("processes", args.processes)
    if hasattr(args, "batch_size") and args.batch_size:
        config.set("batch_size", args.batch_size)
    if hasattr(args, "save_interval"):
        config.set("save_interval", args.save_interval)
    if hasattr(args, "state_dir") and args.state_dir:
        config.set("state_dir", args.state_dir)
    if hasattr(args, "verbosity"):
        config.set("verbosity", args.verbosity)
    if hasattr(args, "log_file") and args.log_file:
        config.set("log_file", args.log_file)
    if hasattr(args, "min_digits"):
        config.set("min_length", args.min_digits)
    if hasattr(args, "max_digits"):
        config.set("max_length", args.max_digits)
    if hasattr(args, "types"):
        config.set("password_types", args.types)

    # Save the configuration
    config.save()


def update_cracker_from_args(cracker: PDFCracker, args, config: Config) -> None:
    """Update cracker settings from arguments and config"""
    # Set batch size
    if hasattr(args, "batch_size") and args.batch_size:
        cracker.batch_size = args.batch_size
    elif config.get("batch_size"):
        cracker.batch_size = config.get("batch_size")

    # Set save interval
    if hasattr(args, "save_interval"):
        cracker.save_interval = args.save_interval
    elif config.get("save_interval"):
        cracker.save_interval = config.get("save_interval")


def main() -> int:
    """Main entry point for the PDF password cracker CLI

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Parse arguments
    parser = create_parser()
    args = parser.parse_args()

    # Load configuration
    config_path = args.config if hasattr(args, "config") else None
    config = Config(config_path)

    # Set up logging
    logger = setup_logger(args, config).get_logger()

    try:
        # Show system information
        print_system_info(logger)

        # Save configuration if requested
        if hasattr(args, "save_config") and args.save_config:
            save_config_from_args(args, config)
            logger.info(f"Configuration saved to {config.config_path}")

        # Initialize cracker
        state_dir = (
            args.state_dir if hasattr(args, "state_dir") else config.get("state_dir")
        )
        processes = (
            args.processes if hasattr(args, "processes") else config.get("processes")
        )

        cracker = PDFCracker(
            pdf_path=args.pdf_file,
            state_dir=state_dir,
            processes=processes,
            logger=logger,
        )

        # Update cracker settings
        update_cracker_from_args(cracker, args, config)

        # Determine strategies
        strategies = (
            args.types
            if hasattr(args, "types") and args.types
            else config.get("password_types", ["smart", "numeric"])
        )

        # Get length parameters
        min_length = (
            args.min_digits
            if hasattr(args, "min_digits")
            else config.get("min_length", 3)
        )
        max_length = (
            args.max_digits
            if hasattr(args, "max_digits")
            else config.get("max_length", 6)
        )
        exact_length = args.digits if hasattr(args, "digits") and args.digits else None

        # Get dictionary path
        dictionary_path = args.dictionary if hasattr(args, "dictionary") else None

        # Start time tracking
        start_time = time.time()

        # Run the cracker
        password = cracker.crack_with_strategy(
            strategies=strategies,
            min_length=min_length,
            max_length=max_length,
            exact_length=exact_length,
            dictionary_path=dictionary_path,
            ignore_state=args.ignore_state if hasattr(args, "ignore_state") else False,
        )

        # Display results
        if password:
            logger.info("Password found!")
            logger.info(f"Password: {password}")
            logger.info(f"Total time: {time.time() - start_time:.2f} seconds")

            # Save to output file if specified
            if hasattr(args, "output_file") and args.output_file:
                with open(args.output_file, "w") as f:
                    f.write(f"PDF: {args.pdf_file}\nPassword: {password}\n")
                logger.info(f"Password saved to {args.output_file}")

            return 0
        else:
            # More prominent message for password not found
            print("\n" + "=" * 60)
            print("PASSWORD NOT FOUND AFTER EXHAUSTING ALL COMBINATIONS")
            print("=" * 60)

            # Summary of what was tried
            strategies_str = ", ".join(strategies)
            length_info = (
                f"exact {exact_length} digits"
                if exact_length
                else f"lengths {min_length} to {max_length} digits"
            )

            logger.warning(f"Exhausted all passwords with strategies: {strategies_str}")
            logger.warning(f"Password length tried: {length_info}")
            logger.info(f"Total time spent: {time.time() - start_time:.2f} seconds")

            # Suggestions for next steps
            print("\nSuggestions for next steps:")
            print("1. Try different password types (-t alphabetic alphanumeric)")
            print("2. Try a different length range (-min and -max)")
            print("3. Try a dictionary-based attack if the password might be a word")
            print(
                "4. Consider if the PDF might be using a non-standard encryption method"
            )
            print(
                "\nExample: pdf-cracker %s -t alphanumeric -min 4 -max 8"
                % args.pdf_file
            )

            return 1

    except PDFCrackerError as e:
        logger.error(f"Error: {str(e)}")
        return 1
    except KeyboardInterrupt:
        logger.info(
            "\nProcess interrupted by user. State saved - you can resume later."
        )
        return 130
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        return 1


def display_examples():
    """Display usage examples"""
    examples = [
        "Basic usage:",
        "  pdf-cracker document.pdf",
        "",
        "Try a specific digit length:",
        "  pdf-cracker document.pdf -d 4",
        "",
        "Try a range of digits:",
        "  pdf-cracker document.pdf -min 3 -max 6",
        "",
        "Control CPU usage:",
        "  pdf-cracker document.pdf -p 2",
        "",
        "Try multiple password types:",
        "  pdf-cracker document.pdf -t numeric alphanumeric",
        "",
        "Dictionary-based attack:",
        "  pdf-cracker document.pdf -t dictionary --dictionary wordlist.txt",
        "",
        "Ignore saved state and start fresh:",
        "  pdf-cracker document.pdf --ignore-state",
        "",
        "Save configuration for future use:",
        "  pdf-cracker document.pdf -t numeric alphabetic -min 4 -max 8 --save-config",
        "",
        "For more options:",
        "  pdf-cracker -h",
    ]

    print("\n".join(examples))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        display_examples()
        sys.exit(1)

    sys.exit(main())
