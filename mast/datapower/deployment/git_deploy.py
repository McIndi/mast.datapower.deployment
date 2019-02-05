from mast.datapower import datapower
from mast.plugin_utils.plugin_utils import render_history, render_results_table
from collections import Counter
from mast.logging import make_logger
from mast.config import get_config
from mast.xor import xorencode, xordecode
from subprocess import Popen
from mast.timestamp import Timestamp
from mast.cli import Cli
from urlparse import urlparse, urlunparse
from urllib import quote_plus
from time import sleep, time
from functools import partial
from collections import OrderedDict, defaultdict
import xml.etree.cElementTree as etree
from os.path import exists
import logging
import subprocess
import shutil
import os
import contextlib


@contextlib.contextmanager
def working_directory(path):
    """A context manager which changes the working directory to the given
    path, and then changes it back to its previous value on exit.
    """
    prev_cwd = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(prev_cwd)

def system_call(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
    ):
    """
    # system_call

    helper function to shell out commands. This should be platform
    agnostic.
    """
    stderr = subprocess.STDOUT
    pipe = subprocess.Popen(
        command,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        shell=shell,
    )
    stdout, stderr = pipe.communicate()
    return stdout, stderr

def quit_for_local_uploads(config_dir):
    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(config_dir)):
        _filename = os.path.join(config_dir, filename)
        tree = etree.parse(_filename)
        files = tree.findall(r'.//files/file')
        local_files = [
            f.get("name") for f in files if f.get("name").startswith("local:")
        ]
        if local_files:
            raise ValueError(
                "configuration '{}' contains files meant to "
                "be uploaded to 'local', this is not allowed. "
                "Use the allow_files_in_export option to perform "
                "this deployment anyway. ".format(
                    filename
                )
            )

DATAPOWER_SERVICE_TYPES = [
    "MultiProtocolGateway",
    "WSGateway",
    "B2BGateway",
    "XMLFirewallService",
    "WebAppFW",
    "WebTokenService",
    "XSLProxyService",
    "HTTPService",
    "TCPProxyService",
    "SSLProxyService",
    "APIGateway",
]

def wait_for_quiesce(appliance, app_domain, services, timeout):
    start = time()
    while True:
        sleep(5)
        done = []
        object_status = appliance.get_status("ObjectStatus", domain=app_domain)
        for service in services:
            _class = service["type"]
            name = service["name"]
            status = list(
                filter(
                    lambda _status: _status.findtext("Class") == _class and _status.findtext("Name") == name,
                    object_status.xml.findall(".//ObjectStatus"),
                )
            )
            if not len(status):
                # Service Does not exist
                done.append(True)
                continue
            status = status[0]
            if status.findtext("ErrorCode") == "in quiescence":
                done.append(True)
            else:
                done.append(False)
        if all(done):
            break
        if time() - start > timeout:
            break

def wait_for_unquiesce(appliance, app_domain, services, timeout):
    start = time()
    while True:
        sleep(5)
        done = []
        object_status = appliance.get_status("ObjectStatus", domain=app_domain)
        for service in services:
            _class = service["type"]
            name = service["name"]
            status = list(
                filter(
                    lambda _status: _status.findtext("Class") == _class and _status.findtext("Name") == name,
                    object_status.xml.findall(".//ObjectStatus"),
                )
            )
            status = status[0]
            if status.findtext("ErrorCode") != "in quiescence":
                done.append(True)
            else:
                done.append(False)
        if all(done):
            break
        if time() - start > timeout:
            break


class Plan(object):
    """A class representing a plan of action for the deployment.
    """
    def __init__(self, config, environment):
        self.config = config
        self.environment = environment
        self.service = config["service"]
        self.deployment_policy = None

        # find the list of steps that need to be followed for each appliance
        self._uploads = self._find_uploads()
        self._merge_deployment_policies()
        self._imports = self._find_imports()
        self._services = self._find_services()
        self._password_map_aliases = self._find_password_map_aliases()

        # find the list of steps that need to be followed for all appliances
        self._actions = self._plan()

        if config["web"]:
            self.output = OrderedDict()
        with open(os.path.join(config["out_dir"], "plan.txt"), "w") as fp:
            for index, action in enumerate(self):
                fp.write("Step {}, {}{}".format(index, action.name, os.linesep))
                for k, v in action.kwargs.items():
                    fp.write("\t{}={}{}".format(k, v, os.linesep))

    def __iter__(self):
        for action in self._actions:
            yield action
        raise StopIteration

    def list_steps(self):
        if self.config["web"]:
            output = OrderedDict()
            output["App Domains"] = ""
            for appliance in self.environment.appliances:
                app_domain = self.config["domains"][self.config["appliances"].index(appliance.hostname)]
                output["App Domains"] += "{} -> {}\n".format(appliance.hostname, app_domain)
            output["Merged Deployment Policies"] = ""
            for filename in self._merged_deployment_policies:
                output["Merged Deployment Policies"] += "{}\n".format(filename)
            output["Services"] = ""
            for kwargs in self._services:
                output["Services"] += "{}: {}\n".format(kwargs["type"], kwargs["name"])
            output["Uploads"] = ""
            for filename, kwargs in self._uploads.items():
                output["Uploads"] += "{} -> {}{}".format(os.path.relpath(kwargs["file_in"], self.config["repo_dir"]), kwargs["file_out"], os.linesep)
            output["Imports"] = ""
            for kwargs in self._imports:
                output["Imports"] += "{}{}".format(os.path.relpath(kwargs["zip_file"], self.config["repo_dir"]), os.linesep)
            output["Password Map Aliases"] = ""
            for kwargs in self._password_map_aliases:
                output["Password Map Aliases"] += "{}{}".format(kwargs["AliasName"], os.linesep)
            return render_results_table(output), render_history(self.environment)
        else:
            print("App Domains")
            for appliance in self.environment.appliances:
                app_domain = self.config["domains"][self.config["appliances"].index(appliance.hostname)]
                print("\t{} -> {}".format(appliance.hostname, app_domain))
            print("Merged DeploymentPolicies")
            for filename in self._merged_deployment_policies:
                print("\t{}".format(filename))
            print("Services")
            for kwargs in self._services:
                print("\t{}: {}".format(kwargs["type"], kwargs["name"]))
            print("-"*80)
            print("Uploads")
            for filename, kwargs in self._uploads.items():
                print("\t{} -> {}".format(os.path.relpath(kwargs["file_in"], self.config["repo_dir"]), kwargs["file_out"]))
            print("Imports")
            for kwargs in self._imports:
                print("\t{}".format(os.path.relpath(kwargs["zip_file"], self.config["repo_dir"])))
            print("Password Map Aliases")
            for kwargs in self._password_map_aliases:
                print("\t{}".format(kwargs["AliasName"]))

    def execute(self):
        log = make_logger("mast.datapower.deployment.git-deploy")
        output = OrderedDict()
        for index, action in enumerate(self):
            print("\nStep {}, {}".format(index, action.name))
            for k, v in action.kwargs.items():
                print("\t{}={}".format(k, v))
            log.info("Executing action '{}'".format(repr(action)))
            response = action()
            try:
                response_tree = response.xml
            except AttributeError:
                # Not an XML response, it is a normal backup
                pass

            log.info(str(response))
            if self.config["web"]:
                key = "{}-{}".format(index, action.name)
                # web mode
                if "CreateDir" in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                    log.info("sleeping for 5 seconds")
                    sleep(5)
                elif "quiesce" in action.name and "unquiesce" not in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                    delay = self.config["quiesce_timeout"] + self.config["quiesce_delay"]
                elif "ObjectStatus" in action.name:
                    output[key] = "Down but Enabled Objects"
                    readings = response_tree.findall(".//ObjectStatus")
                    readings = filter(lambda node: node.findtext("OpState") == "down", readings)
                    readings = filter(lambda node: node.findtext("AdminState") == "enabled", readings)
                    for reading in readings:
                        output[key] += "\n\t{} {} ({})".format(reading.findtext("Class"), reading.findtext("Name"), reading.findtext("ErrorCode"))

                elif "password-map-alias" in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                elif "upload"  in action.name:
                    output[key] = "{} -> {}".format(os.path.relpath(action.kwargs["file_in"], self.config["repo_dir"]), action.kwargs["file_out"])
                    output[key] += "\nResult: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                elif "import" in action.name:
                    output[key] = ""
                    output[key] += "Imported Files"
                    for file_node in response_tree.findall(".//imported-files/*"):
                        output[key] += "\n\t{} {}".format(file_node.get("name"), file_node.get("status"))
                    output[key] += "\nImported Objects"
                    for file_node in response_tree.findall(".//imported-objects/*"):
                        output[key] += "\n\t{} {} {}".format(file_node.get("class"), file_node.get("name"), file_node.get("status"))
                    output[key] += "\nExec Script Results"
                    for file_node in response_tree.findall(".//exec-script-results/*"):
                        output[key] += "\n\t{} {} {}".format(file_node.get("class"), file_node.get("name"), file_node.get("status"))
                elif "unquiesce" in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                elif "remove-oldest-checkpoint" in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                elif "SaveCheckpoint" in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
                elif "NormalBackup" in action.name:
                    output[key] = "Backup can be downloaded above"
                elif "save-config" in action.name:
                    output[key] = "Result: {}".format("\n\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext()))
            if "CreateDir" in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
                log.info("sleeping for 5 seconds")
                sleep(5)
            elif "quiesce" in action.name and "unquiesce" not in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
                delay = self.config["quiesce_timeout"] + self.config["quiesce_delay"]
                wait_for_quiesce(action.appliance, action.kwargs["domain"], self._services, self.config["quiesce_timeout"]+15)
            elif "ObjectStatus" in action.name:
                readings = response_tree.findall(".//ObjectStatus")
                readings = filter(lambda node: node.findtext("OpState") == "down", readings)
                readings = filter(lambda node: node.findtext("AdminState") == "enabled", readings)
                print("\n\tDown but Enabled Objects")
                for reading in readings:
                    print("\t\t{} {} ({})".format(reading.findtext("Class"), reading.findtext("Name"), reading.findtext("ErrorCode")))

            elif "password-map-alias" in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
            elif "upload"  in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
            elif "import" in action.name:
                print("\n\tImported Files")
                for file_node in response_tree.findall(".//imported-files/*"):
                    print("\t\t{} {}".format(file_node.get("name"), file_node.get("status")))
                print("\tImported Objects")
                for file_node in response_tree.findall(".//imported-objects/*"):
                    print("\t\t{} {} {}".format(file_node.get("class"), file_node.get("name"), file_node.get("status")))
                print("\tExec Script Results")
                for file_node in response_tree.findall(".//exec-script-results/*"):
                    print("\t\t{} {} {}".format(file_node.get("class"), file_node.get("name"), file_node.get("status")))
            elif "unquiesce" in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
                wait_for_unquiesce(action.appliance, action.kwargs["domain"], self._services, self.config["timeout"])
            elif "remove-oldest-checkpoint" in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
            elif "SaveCheckpoint" in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
            elif "NormalBackup" in action.name:
                print("\n\tBackup Saved to '{}'".format(action.resp_file))
            elif "save-config" in action.name:
                print("\n\tResult: {}".format("\n\t\t".join(response_tree.find(".//{http://www.datapower.com/schemas/management}result").itertext())))
        if self.config["web"]:
            return render_results_table(output), render_history(self.environment)

    def _find_services(self):
        ret = []
        for kwargs in self._imports:
            xcfg = etree.parse(kwargs["zip_file"])
            for obj in xcfg.findall(r'.//configuration/*'):
                if obj.tag in DATAPOWER_SERVICE_TYPES:
                    service = {
                        "type": obj.tag,
                        "name": obj.get("name"),
                    }                    
                    if service not in ret:
                        ret.append(service)
        return ret

    def _plan(self):
        """Build a plan,
        """
        project_root = self.config["repo_dir"]
        env_dir = os.path.join(project_root, self.config["environment"])
        env_config_dir = os.path.join(env_dir, "config")

        ret = []
        for appliance in self.environment.appliances:
            app_domain = self.config["domains"][self.config["appliances"].index(appliance.hostname)]

            if app_domain not in appliance.domains:
                raise ValueError("Domain '{}' does not exist on appliance '{}'".format(app_domain, appliance.hostname))
            if not self.config["ignore_save_needed"]:
                # when checking appliances domains (three lines above), a
                # domain status request is issued, we reuse this here to
                # see if a save is needed
                domain_status = etree.fromstring(appliance.last_response)
                save_needed = list(
                    filter(
                        lambda n: n.find("Domain").text == app_domain,
                        domain_status.findall(".//DomainStatus")
                    )
                )[0].find("SaveNeeded").text
                if save_needed == "on":
                    raise ValueError(
                        "domain '{}' on appliance '{}' "
                        "needs to be saved. Use ignore_save_needed option "
                        "to deploy anyway".format(
                            appliance.hostname, 
                            app_domain
                        )
                    )

            # Have to get object status first, if we are getting it
            if self.config["object_status"]:
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-ObjectStatus-Before".format(appliance.hostname),
                        appliance.get_status,
                        domain=app_domain,
                        provider="ObjectStatus",
                    )
                )

            if self.config["quiesce"]:
                services_to_quiesce = []
                for kwargs in self._services:
                    if kwargs in services_to_quiesce:
                        continue
                    services_to_quiesce.append(kwargs)
                    ret.append(
                        Action(
                            appliance,
                            self.config,
                            "{}-quiesce".format(appliance.hostname),
                            appliance.ServiceQuiesce,
                            domain=app_domain,
                            timeout=self.config["quiesce_timeout"],
                            delay=self.config["quiesce_delay"],
                            **kwargs
                        )
                    )
            ret.extend(self.get_predeployment_steps(appliance, app_domain))

            for kwargs in self._password_map_aliases:
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-password-map-alias".format(appliance.hostname),
                        appliance.AddPasswordMap,
                        domain=app_domain,
                        **kwargs
                    )
                )
            filestore = appliance.get_filestore(app_domain)
            self.dirs_to_create = defaultdict(list)
            for filename, kwargs in self._uploads.items():
                file_out = kwargs["file_out"]
                if file_out.startswith("local"):
                    target_dir = "/".join(file_out.split("/")[:-1])
                    if not appliance.directory_exists(target_dir, app_domain, filestore) and target_dir not in dirs_to_create:
                        self.dirs_to_create[appliance.hostname].append(target_dir)
                        ret.append(
                            Action(
                                appliance,
                                self.config,
                                "{}-CreateDir".format(appliance.hostname),
                                appliance.CreateDir,
                                domain=app_domain,
                                Dir=target_dir,
                            )
                        )
            for filename, kwargs in self._uploads.items():
                file_out = kwargs["file_out"]
                if file_out.startswith("pubcert"):
                    domain = "default"
                elif file_out.startswith("sharedcert"):
                    domain = "default"
                elif file_out.startswith("cert"):
                    domain = app_domain
                elif file_out.startswith("local"):
                    domain = app_domain
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-upload".format(appliance.hostname),
                        appliance.set_file,
                        domain=domain,
                        **kwargs
                    )
                )

            ret.append(
                Action(
                    appliance,
                    self.config,
                    "{}-import-deployment-policy".format(appliance.hostname),
                    appliance.do_import,
                    domain=app_domain,
                    zip_file=os.path.join(self.config["out_dir"], "merged_deployment_policy.xcfg"),
                    source_type="XML",
                )
            )
            for kwargs in self._imports:
                if env_config_dir in kwargs["zip_file"]:
                    # Do not apply deployment policy to env-specific imports
                    ret.append(
                        Action(
                            appliance,
                            self.config,
                            "{}-import".format(appliance.hostname),
                            appliance.do_import,
                            domain=app_domain,
                            **kwargs
                        )
                    )
                else:
                    ret.append(
                        Action(
                            appliance,
                            self.config,
                            "{}-import".format(appliance.hostname),
                            appliance.do_import,
                            domain=app_domain,
                            deployment_policy=self.deployment_policy,
                            **kwargs
                        )
                    )

            if self.config["quiesce"]:
                for kwargs in services_to_quiesce:
                    ret.append(
                        Action(
                            appliance,
                            self.config,
                            "{}-unquiesce".format(appliance.hostname),
                            appliance.ServiceUnquiesce,
                            domain=app_domain,
                            **kwargs
                        )
                    )

            # save configuration
            if self.config["save_config"]:
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-save-config".format(appliance.hostname),
                        appliance.SaveConfig,
                        domain=app_domain
                    )
                )
            # Get object status after we are all done
            if self.config["object_status"]:
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-ObjectStatus-After".format(appliance.hostname),
                        appliance.get_status,
                        domain=app_domain,
                        provider="ObjectStatus",
                    )
                )
        return ret


    def _find_imports(self):
        project_root = self.config["repo_dir"]
        env_dir = os.path.join(project_root, self.config["environment"])
        env_config_dir = os.path.join(env_dir, "config")
        common_config_dir = os.path.join(project_root, "config")

        ret = []

        services = []

        # Service imports
        if exists(common_config_dir):
            if not self.config["allow_files_in_export"]:
                quit_for_local_uploads(common_config_dir)
            ret.extend(
                [
                    {
                        "zip_file": os.path.join(common_config_dir, filename),
                        "source_type": "XML",
                    }
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_config_dir))
                ]
            )

        if exists(env_config_dir):
            if not self.config["allow_files_in_export"]:
                quit_for_local_uploads(env_config_dir)
            ret.extend(
                [
                    {
                        "zip_file": os.path.join(env_config_dir, filename),
                        "source_type": "XML"
                    }
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_config_dir))
                ]
            )
        return ret


    def get_predeployment_steps(self, appliance, app_domain):
        """Predeployment now consiste of a checkpoint and normal backup
        in the default domain and the app domain.
        """
        ret = []
        if self.config["checkpoint_app_domain"]:
            if len(appliance.get_existing_checkpoints(app_domain)) == appliance.max_checkpoints(app_domain):
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-remove-oldest-checkpoint".format(appliance.hostname),
                        appliance.remove_oldest_checkpoint,
                        domain=app_domain,
                    )
                )
            ret.append(
                Action(
                    appliance,
                    self.config,
                    "{}-SaveCheckpoint".format(appliance.hostname),
                    appliance.SaveCheckpoint,
                    domain=app_domain,
                    ChkName="{}_{}".format(
                        app_domain,
                        Timestamp().epoch
                    )
                )
            )
        if self.config["checkpoint_default_domain"]:
            if len(appliance.get_existing_checkpoints("default")) == appliance.max_checkpoints("default"):
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-remove-oldest-checkpoint".format(appliance.hostname),
                        appliance.remove_oldest_checkpoint,
                        domain="default",
                    )
                )
            ret.append(
                Action(
                    appliance,
                    self.config,
                    "{}-SaveCheckpoint".format(appliance.hostname),
                    appliance.SaveCheckpoint,
                    domain="default",
                    ChkName="{}_{}".format(
                        "default",
                        Timestamp().epoch
                    )
                )
            )

        if self.config["backup_app_domain"]:
            ret.append(
                Action(
                    appliance,
                    self.config,
                    "{}-NormalBackup".format(appliance.hostname),
                    appliance.get_normal_backup,
                    domains=app_domain,
                )
            )
        if self.config["backup_default_domain"]:
            ret.append(
                Action(
                    appliance,
                    self.config,
                    "{}-NormalBackup".format(appliance.hostname),
                    appliance.get_normal_backup,
                    domains="default",
                )
            )
        return ret

    def _find_uploads(self):
        ret = {}
        project_root = self.config["repo_dir"]
        env_dir = os.path.join(project_root, self.config["environment"])

        # upload directories
        env_local_dir = os.path.join(env_dir, "local")
        env_cert_dir = os.path.join(env_dir, "cert")
        env_sharedcert_dir = os.path.join(env_dir, "sharedcert")
        env_pubcert_dir = os.path.join(env_dir, "pubcert")
        common_local_dir = os.path.join(project_root, "local")
        common_cert_dir = os.path.join(project_root, "cert")
        common_sharedcert_dir = os.path.join(project_root, "sharedcert")
        common_pubcert_dir = os.path.join(project_root, "pubcert")



        # gather uploads
        if exists(common_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_pubcert_dir)):
                file_out = "pubcert:///{}".format(filename)
                ret[file_out] = {
                        "file_in": os.path.join(common_pubcert_dir, filename),
                        "file_out": file_out,
                }
        if exists(common_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_cert_dir)):
                file_out = "cert:///{}".format(filename)
                ret[file_out] = {
                        "file_in": os.path.join(common_cert_dir, filename),
                        "file_out": file_out,
                }
        if exists(common_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_sharedcert_dir)):
                file_out = "sharedcert:///{}".format(filename)
                ret[file_out] = {
                        "file_in": os.path.join(common_sharedcert_dir, filename),
                        "file_out": file_out,
                }
        if exists(env_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_pubcert_dir)):
                file_out = "pubcert:///{}".format(filename)
                ret[file_out] = {
                        "file_in": os.path.join(env_pubcert_dir, filename),
                        "file_out": file_out,
                }
        if exists(env_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_cert_dir)):
                file_out = "cert:///{}".format(filename)
                ret[file_out] = {
                        "file_in": os.path.join(env_cert_dir, filename),
                        "file_out": file_out,
                }
        if exists(env_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_sharedcert_dir)):
                file_out = "sharedcert:///{}".format(filename)
                ret[file_out] = {
                        "file_in": os.path.join(env_sharedcert_dir, filename),
                        "file_out": file_out,
                }
        if exists(common_local_dir):
            for root, dirs, files in os.walk(common_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(common_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        ret[file_out] = {
                                "file_in": os.path.join(root, filename),
                                "file_out": file_out,
                        }
        if exists(env_local_dir):
            for root, dirs, files in os.walk(env_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(env_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        ret[file_out] = {
                                "file_in": os.path.join(root, filename),
                                "file_out": file_out,
                        }
        return ret

    def _find_password_map_aliases(self):
        ret = []

        project_root = self.config["repo_dir"]
        env_dir = os.path.join(project_root, self.config["environment"])
        # Password alias
        env_password_alias_file = os.path.join(env_dir, "password", "alias-password.map")
        common_password_alias_file = os.path.join(project_root, "password", "alias-password.map")

        # password alias
        if exists(common_password_alias_file):
            with open(common_password_alias_file, "r") as fp:
                for line in fp:
                    name, password = xordecode(line).split(":")
                    ret.append(
                        {
                            "AliasName": name.strip(),
                            "Password": password.strip(),
                        }
                    )
        if exists(env_password_alias_file):
            with open(env_password_alias_file, "r") as fp:
                for line in fp:
                    name, password = xordecode(line).split(":")
                    ret.append(
                        {
                            "AliasName": name.strip(),
                            "Password": password.strip(),
                        }
                    )
        return ret

    def _merge_deployment_policies(self):
        ret = []
        project_root = self.config["repo_dir"]
        env_dir = os.path.join(project_root, self.config["environment"])
        env_deppol_dir = os.path.join(env_dir, "DeploymentPolicy")
        common_deppol_dir = os.path.join(project_root, "DeploymentPolicy")
        self._merged_deployment_policies = []
        # Get deployment policy
        if exists(env_deppol_dir):
            if len(filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))) > 1:
                raise ValueError("Only one deployment policy permitted In an environmental directory.")
            deployment_policy_filename = filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))[0]
            deployment_policy_filename = os.path.join(env_deppol_dir, deployment_policy_filename)
            self._merged_deployment_policies.append(os.path.relpath(deployment_policy_filename, self.config["repo_dir"]))
            env_tree = etree.parse(deployment_policy_filename)
            self.deployment_policy = env_tree.find(".//ConfigDeploymentPolicy").get("name")
        else:
            raise ValueError("Could not find expected DeploymentPolicy directory at '{}'".format(env_deppol_dir))
        if exists(common_deppol_dir):
            if len(filter(lambda x: "EMPTY" not in x, os.listdir(common_deppol_dir))) > 1:
                raise ValueError("Only one deployment policy permitted In an environmental directory.")
            deployment_policy_filename = filter(lambda x: "EMPTY" not in x, os.listdir(common_deppol_dir))
            if len(deployment_policy_filename):
                deployment_policy_filename = deployment_policy_filename[0]
                deployment_policy_filename = os.path.join(common_deppol_dir, deployment_policy_filename)
                self._merged_deployment_policies.append(os.path.relpath(deployment_policy_filename, self.config["repo_dir"]))
                common_tree = etree.parse(deployment_policy_filename)
                deppol = env_tree.find(".//ConfigDeploymentPolicy")
                # AcceptedConfig
                i = list(deppol).index(deppol.findall("AcceptedConfig")[-1]) + 1
                for node in common_tree.findall(".//ConfigDeploymentPolicy/AcceptedConfig"):
                    deppol.insert(i, node)
                    i += 1
                # FilteredConfig
                i = list(deppol).index(deppol.findall("FilteredConfig")[-1]) + 1
                for node in common_tree.findall(".//ConfigDeploymentPolicy/FilteredConfig"):
                    deppol.insert(i, node)
                    i += 1
                # ModifiedConfig
                i = list(deppol).index(deppol.findall("FilteredConfig")[-1]) + 1
                for node in common_tree.findall(".//ConfigDeploymentPolicy/ModifiedConfig"):
                    deppol.insert(i, node)
                    i += 1
        with open(os.path.join(self.config["out_dir"], "merged_deployment_policy.xcfg"), "w") as fp:
            fp.write(etree.tostring(env_tree.getroot()))

class Action(object):
    """A class representing a action to be taken as
    part of a deployment.

    This is a fairly simple wrapper around
    ``functools.partial()``. It is a callable
    action which executes a function, but there
    is some more features which are designed to
    allow easy construction of plans
    """
    def __init__(self, appliance, config, *args, **kwargs):
        self.appliance  = appliance
        self.config = config
        self.name = args[0]
        self.args = args
        self.kwargs = kwargs
        self.callable = partial(args[1], *args[2:], **kwargs)

    def __call__(self):
        log = make_logger("mast.datapower.deployment.git-deploy")

        ret = self.callable()
        req_file = os.path.join(
            self.config["out_dir"],
            "{}-{}-{}.xml".format(
                self.config["step_number"],
                "request",
                self.name,
            )
        )
        resp_file = os.path.join(
            self.config["out_dir"],
            "{}-{}-{}.xml".format(
                self.config["step_number"],
                "response",
                self.name,
            )
        )
        if "NormalBackup" in self.name:
            resp_file = resp_file.replace(".xml", ".zip")
        self.req_file = req_file
        self.resp_file = resp_file
        with open(req_file, "w") as fp:
            fp.write(str(self.appliance.request))
        with open(resp_file, "w") as fp:
            if "NormalBackup" in self.name:
                fp.write(ret)
            else:
                try:
                    fp.write(self.appliance.last_response)
                except TypeError:
                    fp.write(str(self.appliance.last_response))
        self.config["step_number"] += 1
        return ret

    def __str__(self):
        return "\n".join(
            [
                "{}={}".format(k, repr(v)) for k, v in self.kwargs.items() if "password" not in k.lower()
            ]
        )

    def __repr__(self):
        return "{}({})".format(
            self.name,
            ", ".join(
                [
                    "{}={}".format(k, repr(v)) for k, v in self.kwargs.items() if "password" not in k.lower()
                ]
            )
        )

def parse_config(appliances, credentials, environment, service):
    config_filename = os.path.join(os.environ.get("MAST_HOME"), "etc", "local", "service-config.conf")
    if not os.path.exists(config_filename):
        raise ValueError("Did not find configuration at '{}'".format(config_filename))
    with open(config_filename, "r") as fp:
        headers = list(
            filter(
                lambda line: line.startswith("["),
                fp
            )
        )
    if len(headers) != len(set(headers)):
        duplicates = [k for k,v in Counter(headers).items() if v>1]
        raise ValueError("Duplicate header(s) {} found in '{}'".format(duplicates, config_filename))
    config = get_config("service-config.conf")
    ret = {
        "appliances": [],
        "credentials": [],
        "domains": [],
        "environment": environment,
    }
    for index, appliance in enumerate(appliances):
        domain = config.get(
            service,
            "{}-{}".format(appliance, environment),
            None
        )
        if domain is None:
            raise ValueError("Appliance '{}' not part of environment '{}'".format(
                appliance, environment
            ))
        ret["appliances"].append(appliance)
        if len(credentials) == 1:
            ret["credentials"].append(credentials[0])
        else:
            try:
                ret["credentials"].append(credentials[index])
            except IndexError:
                raise ValueError("Must provide either one set of credentials or one set for each appliance")
        ret["domains"].append(domain)
    ret.update(config.items(service))
    if "git-credentials" in ret:
        username, password = xordecode(ret["git-credentials"]).split(":")
        url = urlparse(ret["repo"])
        ret["repo"] = "{}://{}:{}@{}{}".format(
            url.scheme,
            quote_plus(username),
            quote_plus(password),
            url.netloc,
            url.path,
        )
    return ret


def _prepare_output_directories(config, out_dir):
    """Ensure that output directories exist, add absolute paths to config
    """
    log = make_logger("mast.datapower.deployment.git-deploy")
    # Build the paths for out, audit and repo
    if not out_dir:
        out_dir = os.path.join(os.environ["MAST_HOME"], "tmp", "deployment-results")
    config["out_dir"] = out_dir
    config["audit_dir"] = os.path.join(out_dir, "audit")
    config["repo_dir"] = os.path.join(out_dir, config["service"])
    if "subdirectory" in config:
        config["repo_dir"] = os.path.join(config["repo_dir"], config["subdirectory"])

    # Create the out and audit directories if needed
    if not os.path.exists(config["out_dir"]):
        log.info("'{}' does not exist, creating...".format(config["out_dir"]))
        os.makedirs(config["out_dir"])
    if not os.path.exists(config["audit_dir"]):
        log.info("'{}' does not exist, creating...".format(config["audit_dir"]))
        os.makedirs(config["audit_dir"])


def _initialize_logging(config):
    """Add a custom logging handler so we can include the logs in
    the post-deployment artifacts
    """
    log = make_logger("mast.datapower.deployment.git-deploy")
    handler = logging.FileHandler(
        os.path.join(
            config["out_dir"],
            "deployment.log"
        ),
        "w"
    )
    formatter = logging.Formatter("%(asctime)s: %(levelname)s: %(relativeCreated)d: %(message)s")
    handler.setFormatter(formatter)
    log.addHandler(handler)

def _clone_pull_and_checkout(config):
    """Either pull latest changes or clone the remote repository
    """
    log = make_logger("mast.datapower.deployment.git-deploy")
    if exists(config["repo_dir"]):
        log.info("Existing local repository found, pulling latest changes")
        with working_directory(config["repo_dir"]):
            out, err = system_call("git pull")
    else:
        log.info("cloning repo '{}' to '{}'".format(config["repo"], config["repo_dir"]))
        out, err = system_call("git clone {} {}".format(config["repo"], config["repo_dir"]))
    log.info("stdout from git: '{}'".format(out))
    log.info("stderr from git: '{}'".format(err))            
    # If commit is provided, perform a git checkout
    if config["commit"]:
        with working_directory(config["repo_dir"]):
            log.info("performing 'git checkout {}'".format(config["commit"]))
            out, err = system_call("git checkout {}".format(config["commit"]))
        log.info("stdout from git checkout: '{}'".format(out))
        log.info("stderr from git checkout: '{}'".format(err))

def git_deploy(
        appliances=[],
        credentials=[],
        timeout=120,
        no_check_hostname=False,
        environment="",
        service="",
        commit="",
        out_dir="",
        dry_run=False,
        allow_files_in_export=False,
        ignore_save_needed=False,
        quiesce=True,
        object_status=True,
        backup_app_domain=True,
        backup_default_domain=True,
        checkpoint_app_domain=True,
        checkpoint_default_domain=True,
        quiesce_delay=0,
        quiesce_timeout=60,
        save_config=False,
        web=False,
    ):
    """
    Deploy services to IBM DataPower appliances. A service must be
    configured in $MAST_HOME/etc/local/service-config.conf, please
    see $MAST_HOME/etc/default/service-config.conf for documentation
    on the format of this configuration file.
				
Parameters:

* `-a, --appliances`: The hostname(s), ip address(es), environment name(s)
or alias(es) of the appliances you would like to affect. For details
on configuring environments please see the comments in
`environments.conf` located in `$MAST_HOME/etc/default`. For details
on configuring aliases, please see the comments in `hosts.conf` located in
`$MAST_HOME/etc/default`. To pass multiple arguments to this parameter,
use multiple entries of the form `[-a appliance1 [-a appliance2...]]`
* `-c, --credentials`: The credentials to use for authenticating to the
appliances. Should be either one set to use for all appliances
or one set for each appliance. Credentials should be in the form
`username:password`. To pass multiple credentials to this parameter, use
multiple entries of the form `[-c credential1 [-c credential2...]]`.
When referencing multiple appliances with multiple credentials,
there must be a one-to-one correspondence of credentials to appliances:
`[-a appliance1 [-a appliance2...]] [-c credential1 [-c credential2...]]`
If you would prefer to not use plain-text passwords,
you can use the output of `$ mast-system xor <username:password>`.
* `-t, --timeout`: The timeout in seconds to wait for a response from
an appliance for any single request. __NOTE__ Program execution may
halt if a timeout is reached.
* `-n, --no-check-hostname`: If specified SSL verification will be turned
off when sending commands to the appliances.
* `-e, --environment`: The environment must be defined in the service-config.conf
* `-s, --service`: The service to deploy, this corresponds to a stanza in service-config.conf
* `-c, --commit`: The commit id, commit tag or branch for which to perform a git checkout
* `-o, --out_dir`: The directory in which to store the deployment artifacts
* `-d, --dry_run`: If specified, nothing will be done to the appliances
* `--ignore-save-needed`: If specified, deployment will proceed regardless of whether
the app domain needs to be saved 
* `--allow-files-in-export`: regardless of whether there are local
uploads within configuration exports
* `-N, --no-quiesce`: If specified, the service will not be quiesced before the
deployment
* `-q, --quiesce-delay`: The number of seconds the datapower will wait
before quiescing the service
* `-Q, --quiesce-timeout`: The maximum number of seconds for the datapower to
wait for the service to quiesce before abruptly terminating it.
* `-s, --save-config`: If specified, the app domains configuration will be
saved after the deployment is complete
    """
    log = make_logger("mast.datapower.deployment.git-deploy")

    config = parse_config(appliances, credentials, environment, service)
    config.update(
        {
            "allow_files_in_export": allow_files_in_export,
            "ignore_save_needed": ignore_save_needed,
            "quiesce": quiesce,
            "quiesce_delay": quiesce_delay,
            "quiesce_timeout": quiesce_timeout,
            "save_config": save_config,
            "step_number": 0,
            "object_status": object_status,
            "backup_app_domain": backup_app_domain,
            "backup_default_domain": backup_default_domain,
            "checkpoint_app_domain": checkpoint_app_domain,
            "checkpoint_default_domain": checkpoint_default_domain,
            "commit": commit,
            "service": service,
            "timeout": timeout,
            "web": web,
        }
    )
    # This adds paths to config and creates the directories as needed
    _prepare_output_directories(config, out_dir)

    _initialize_logging(config)

    log.info("Working with path: '{}'".format(os.environ.get("PATH")))

    _clone_pull_and_checkout(config)

    environment = datapower.Environment(
        config["appliances"],
        credentials=config["credentials"],
        check_hostname=not no_check_hostname,
        timeout=timeout,
    )

    plan = Plan(config, environment)

    if dry_run:
        return plan.list_steps()
    else:
        return plan.execute()


if __name__ == "__main__":
    cli = Cli(main=main, description=main.__doc__)
    try:
        cli.run()
    except SystemExit:
        pass
    except:
        make_logger("mast.datapower.deployment.git-deploy").exception("An unhandled exception occurred")
        raise

