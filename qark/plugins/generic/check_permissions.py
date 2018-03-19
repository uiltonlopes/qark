import logging
import re

import javalang
from qark.issue import Severity, Issue
from qark.plugins.helpers import java_files_from_files
from qark.scanner.plugin import BasePlugin

log = logging.getLogger(__name__)

CHECK_PERMISSIONS_DESCRIPTION = (
    "Be careful with use of {used_permission} permission function\nApp maybe vulnerable to Privilege escalation or "
    "Confused Deputy Attack. This function can grant access to malicious application, lacking the "
    "appropriate permission, by assuming your applications permissions. This means a malicious application, "
    "without appropriate permissions, can bypass its permission check by using your application"
    "permission to get access to otherwise denied resources. Use - {recommended_permission}CallingPermission instead. "
    "Reference: https://developer.android.com/reference/android/content/Context.html\n"
)
CHECK_PERMISSION_REGEX = re.compile(r'checkCallingOrSelfPermission|checkCallingOrSelfUriPermission|checkPermission')
ENFORCE_PERMISSION_REGEX = re.compile(
    'enforceCallingOrSelfPermission|enforceCallingOrSelfUriPermission|enforcePermission')


class CheckPermissions(BasePlugin):
    def __init__(self):
        BasePlugin.__init__(self, category="manifest", name="Potientially vulnerable check permission function called",
                            description=CHECK_PERMISSIONS_DESCRIPTION)
        self.severity = Severity.WARNING

    def run(self, files, apk_constants=None):
        java_files = java_files_from_files(files)

        for java_file in java_files:
            self._process(java_file)

    def _process(self, java_file):
        try:
            with open(java_file, "r") as java_file_to_read:
                file_contents = java_file_to_read.read()
        except IOError:
            log.debug("File does not exist %s, continuing", java_file)
            return

        try:
            tree = javalang.parse.parse(file_contents)
        except (javalang.parser.JavaSyntaxError, IndexError):
            log.debug("Error parsing file %s, continuing", java_file)
            return

        if any(["Service" in imp for imp in tree.imports]):
            if re.search(CHECK_PERMISSION_REGEX, file_contents):
                self.issues.append(Issue(
                    category=self.category, severity=self.severity, name=self.name,
                    description=self.description.format(used_permission="Check", recommended_permission="check"),
                    file_object=java_file)
                )
            elif re.search(ENFORCE_PERMISSION_REGEX, file_contents):
                self.issues.append(Issue(
                    category=self.category, severity=self.severity, name=self.name,
                    description=self.description.format(used_permission="Enforce", recommended_permission="enforce"),
                    file_object=java_file)
                )


plugin = CheckPermissions()