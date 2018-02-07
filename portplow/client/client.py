'''
license...
'''

# Standard libraries
import json
import logging
import os
import requests
import sys
import shlex
import tempfile
from datetime import datetime
from distutils.dir_util import mkpath, DistutilsFileError
from subprocess import Popen, PIPE, STDOUT
from time import sleep

'''
Setup logging to stdout for informational messages and console for
everything else.
'''
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/var/opt/portplow/client.log',
                    filemode='a+')

# Attempt to use the coloredlogs library if available
try:
    import coloredlogs
    formatter = coloredlogs.ColoredFormatter(fmt='%(name)-12s: %(levelname)-8s %(message)s')
except ImportError:
    logging.getLogger('').warn("Colorized logs disabled. Install coloredlogs to use.")
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')

console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

VALID_TOOLS = [
    "/usr/bin/nmap",
    "/opt/portplow/masscan/bin/masscan"
]


class Job(object):

    log = logging.getLogger('job')

    def __init__(self, **kwargs):
        self.id = kwargs.get('id', None)
        self.status = kwargs.get('status', None)
        self.command = kwargs.get('command', None)
        self.return_code = kwargs.get('return_code', None)
        self.stdout = kwargs.get('stdout', None)
        self.stderr = kwargs.get('stderr', None)
        self.attempt = kwargs.get('attempt', 0)
        self.files = kwargs.get('files', None)
        self.tool = kwargs.get('tool', None)

        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")
        self.output_dir = os.path.join(os.environ.get('PORTPLOW_DIR', '/tmp'),
                                       "results",
                                       str(self.id),
                                       timestamp)
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except TypeError:
            try:
                mkpath(self.output_dir)
            except DistutilsFileError:
                self.log.error("Cannot create output directory.")

        # Tack on the path to the command
        if self.tool in VALID_TOOLS:
            self.command = "{} {}".format(self.tool, self.command)
        else:
            self.log.error("An invalid tool was specified!")
            self.command = "/bin/false"

        self.log.debug("Job created: {}".format(kwargs))

    def json_ready(self):
        # TODO: grab files if the job is complete.
        return {
            "id": self.id,
            "attempt": self.attempt,
            "status": self.status,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class JobMonitor:
    """Job monitor class
    """

    # Client constants
    READY = "ready"
    IN_USE = "in_use"

    # Job constants
    PENDING = 'P'
    EXECUTING = 'E'
    RETRY = 'R'
    KILLED = 'K'
    COMPLETE = 'C'
    HOLD = 'H'
    ERROR = 'X'

    def __init__(self, target_url=None, token=None, delay=3):

        # Get environmental variables if available.
        self.target_url = os.environ.get("PORTPLOW_URL", target_url)
        self.token = os.environ.get("PORTPLOW_TOKEN", token)
        try:
            self.delay = int(os.environ.get("PORTPLOW_DELAY", delay))
        except ValueError:
            raise Exception("Delay is not an integer. Please fix.")

        if self.target_url is None:
            raise Exception("Target URL is not set.")

        if self.token is None:
            raise Exception("Token is not set.")

        self.log = logging.getLogger('job_monitor')

        # Process tracking variables
        self.process = None
        self.pid = None

        # Initial job object
        self.ready_state()

        # HTTP session
        self.s = requests.Session()
        self.s.headers.update({"Authentication": "ScannerToken {}".format(self.token),
                               "Content-Type": "application/json"})

    def get_job(self):
        """
        Check if a job was returned. If so, kickoff job.
        :return:
        """
        ''' Get job from response '''

        if self.status != self.READY:
            self.log.debug("Skipping get_job since we aren't in a ready status.")
            return

        if self.response is None:
            self.log.debug("Skipping get_job because response is None.")
            return

        self.log.debug("See if a job was returned by the server.")

        if "jobs" not in self.response:
            self.log.debug("Jobs weren't in the response. Malformed response?")
            print("Response. {}".format(self.response))
        elif len(self.response["jobs"]) > 0 and self.job is not None:
            self.log.debug("Jobs were returned but we already have one.")
        else:
            self.job = Job(**self.response['jobs'][0])
            self.log.debug("New job received. {}"
                           .format(json.dumps(self.response['jobs'][0])))
            command = shlex.split(self.job.command)
            self.log.debug("Command to run: {}".format(command))
            # command_log = os.path.join(self.job.output_dir, "output.log")
            self.tmp_stdout = tempfile.TemporaryFile()
            self.tmp_stderr = tempfile.TemporaryFile()
            self.process = Popen(command,
                                 # stdout=open(command_log, 'a+'),
                                 # stderr=STDOUT,
                                 stdout=self.tmp_stdout,
                                 stderr=self.tmp_stderr,
                                 bufsize=-1,
                                 cwd=self.job.output_dir)
            self.pid = self.process.pid
            self.job.status = self.EXECUTING
            self.status = self.IN_USE
            self.send_update()

    def send_update(self):
        """
        Send updates to the server.
        """
        self.log.info("Sending update to server.")

        data = {'status': self.status}

        if self.job is not None:
            data["jobs"] = [self.job.json_ready()]

        server_response = self.s.post(self.target_url, data=json.dumps(data))
        if server_response.status_code == 200:
            response = server_response.json()
            if "message" in server_response:
                if response["message"] == "kill_all":
                    self.process.kill()

            self.response = response
            self.log.debug("Server response returned {}".format(server_response.json()))
        else:
            self.log.error("Server had an issue. Returned ({}). Content: {}".format(server_response.status_code, server_response.content))

    def check_status(self):
        """Check the status of the running process."""
        self.log.debug("Checking process status")

        # Don't bother if we're not executing.
        if self.status != self.IN_USE:
            self.log.debug("No current jobs running.")
            return

        if self.process:
            self.log.debug("There is a process.")
            if self.process.poll() is not None:
                self.log.debug("Process {} is complete. Return code is {}".format(self.process.pid, self.process.returncode))

                stdout, stderr = self.process.communicate()

                if self.process.returncode != 0:
                    self.job.status = self.ERROR
                else:
                    self.job.status = self.COMPLETE

                self.job.return_code = self.process.returncode
                self.tmp_stdout.seek(0)
                self.tmp_stderr.seek(0)
                self.job.stdout = self.tmp_stdout.read()
                self.job.stderr = self.tmp_stderr.read()

                # Blank out process and job
                self.process = None
                self.send_update()
                self.ready_state()
            else:
                self.log.debug("Process is still running.")

    def ready_state(self):
        """Reset job to defaults."""
        self.status = self.READY
        self.job = None
        self.process = None
        self.response = None
        # self.data = {"status": self.READY, "jobs": [{}]}

    def start(self):
        """Starting loop function."""
        self.send_update()

        while True:
            self.log.debug("Job status: {}. Running PID: {}".format(self.status, self.pid))
            # data = json.dumps(self.data)
            # r = self.s.post(self.target_url, data=data)
            # self.response = r.json()
            self.check_status()
            self.send_update()
            self.get_job()
            sleep(self.delay)


def run_client():
    try:
        job_monitor = JobMonitor()
        job_monitor.start()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise

if __name__ == "__main__":
    run_client()
