import logging
import os
import sys
import atexit
from datetime import datetime
import traceback

class Logger:
    def __init__(self, log_name='app_log', log_level=logging.DEBUG, console_log_level=logging.DEBUG, file_log_level=logging.DEBUG):
        self.log_name = log_name
        self.log_level = log_level
        self.console_log_level = console_log_level
        self.file_log_level = file_log_level
        self.logger = self._setup_logger()
        self._setup_exit_trap()

    def _setup_logger(self):
        # Create a folder with the current date
        log_folder = 'log/' + datetime.now().strftime('%Y-%m-%d')
        os.makedirs(log_folder, exist_ok=True)

        # Set up the logger
        logger = logging.getLogger(self.log_name)
        logger.setLevel(self.log_level)

        # Create a file handler
        log_file = os.path.join(log_folder, f"{self.log_name}.log")
        self.file_handler = logging.FileHandler(log_file)
        self.file_handler.setLevel(self.file_log_level)

        # Create a console handler
        self.console_handler = logging.StreamHandler()
        self.console_handler.setLevel(self.console_log_level)

        # Create a logging format
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.file_handler.setFormatter(formatter)
        self.console_handler.setFormatter(formatter)

        # Add handlers to the logger
        logger.addHandler(self.file_handler)
        logger.addHandler(self.console_handler)

        return logger

    def _setup_exit_trap(self):
        # Ensure that the logger will be cleaned up on exit
        import atexit
        atexit.register(self._cleanup_logger)

    def _cleanup_logger(self):
        handlers = self.logger.handlers[:]
        for handler in handlers:
            handler.close()
            self.logger.removeHandler(handler)

    def set_console_log_level(self, log_level):
        self.console_handler.setLevel(log_level)

    def set_file_log_level(self, log_level):
        self.file_handler.setLevel(log_level)

    def _setup_exit_trap(self):
        atexit.register(self._exit_handler)
        sys.excepthook = self._exception_handler

    def _exit_handler(self):
        if hasattr(sys, 'last_type'):
            self.logger.error(f"Program exited with unhandled exception: {sys.last_value}", exc_info=(sys.last_type, sys.last_value, sys.last_traceback))
        else:
            self.logger.info("Program exited normally.")

    def _exception_handler(self, exctype, value, tb):
        self.logger.error(f"Unhandled exception: {value}", exc_info=(exctype, value, tb))
        self._log_local_variables(tb)
        # Save the exception details to sys for the exit handler to use
        sys.last_type, sys.last_value, sys.last_traceback = exctype, value, tb
        # Call the default excepthook to ensure the program terminates
        sys.__excepthook__(exctype, value, tb)

    def _log_local_variables(self, tb):
        while tb:
            frame = tb.tb_frame
            lineno = tb.tb_lineno
            code = frame.f_code
            filename = code.co_filename
            function = code.co_name
            local_vars = frame.f_locals

            self.logger.error(f"Local variables in frame {function} at {filename}:{lineno}")
            for var_name, var_value in local_vars.items():
                self.logger.error(f"    {var_name} = {var_value}")

            tb = tb.tb_next

    def get_logger(self):
        return self.logger

# Usage example
if __name__ == "__main__":
    # Create a logger instance
    logger = Logger(log_level=logging.DEBUG).get_logger()

    # Log messages with different verbosity levels
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")

    # Example to raise an exception to test the logging of unhandled exceptions and local variables
    def test_function():
        local_var1 = "test value"
        local_var2 = 42
        raise ValueError("This is a test exception with local variables")

    test_function()
