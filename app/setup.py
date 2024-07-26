import subprocess
import winsound

from .Gui.messagebox import MessageBox


class Setup:
    """
    A class that handles the setup process for the packetSniffer application.
    """

    @staticmethod
    def import_required_modules():
        """
        Installs the required modules for the packetSniffer application.

        This method uses the `subprocess` module to execute pip commands and install the following modules:
        - customtkinter
        - scapy
        - psutil

        If any of the pip commands fail, an error message is printed.

        Note: This method assumes that Python version 3.12 or greater is already installed.

        Raises:
            subprocess.CalledProcessError: If any of the pip commands fail.
        """
        try:
            subprocess.check_call(["pip", "install", "customtkinter"])
            subprocess.check_call(["pip", "install", "scapy"])
            subprocess.check_call(["pip", "install", "psutil"])
            subprocess.check_call(['pip', 'install', 'requests'])
            subprocess.check_call(['pip', 'install', 'matplotlib'])

        except subprocess.CalledProcessError:
            winsound.MessageBeep()
            MessageBox.showerror(title='ERROR', message="Please make sure you have python 3.11 or greater installed")
