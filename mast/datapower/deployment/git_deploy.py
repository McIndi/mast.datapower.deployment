from mast.datapower import datapower
from mast.plugin_utils.plugin_utils import render_history, render_results_table
from mast.logging import make_logger
from mast.config import get_config
from mast.xor import xorencode, xordecode
from subprocess import Popen
from mast.timestamp import Timestamp
from mast.cli import Cli
from urlparse import urlparse, urlunparse
from urllib import quote_plus
from time import sleep
from functools import partial
from collections import OrderedDict
import xml.etree.cElementTree as etree
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
        shell=False):
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
        shell=shell)
    stdout, stderr = pipe.communicate()
    return stdout, stderr

def exists(path):
    return os.path.exists(path)

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
                "Use the force option to perform this deployment anyway. ".format(
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

class Plan(object):
    """A class representing a plan of action for the deployment.
    """
    def __init__(self, config, environment, service):
        self.config = config
        self.environment = environment
        self.service = service
        self._actions = self._plan()

    def __iter__(self):
        for action in self._actions:
            yield action
        raise StopIteration


    def _plan(self):
        """Build a plan,
        """
        ret = []
        for appliance in self.environment.appliances:
            app_domain = self.config["domains"][self.config["appliances"].index(appliance.hostname)]
            if app_domain  not in appliance.domains:
                raise ValueError("Domain '{}' does not exist on appliance '{}'")
            # when checking appliances domains (two lines above), a
            # domain status request is issued, we reuse this here to
            # see if a save is needed
            if not self.config["force"]:
                domain_status = etree.fromstring(appliance.last_response)
                save_needed = list(filter(
                    lambda n: n.find("Domain").text == app_domain,
                    domain_status.findall(".//DomainStatus")
                ))[0].find("SaveNeeded").text
                if save_needed == "on":
                    raise ValueError(
                        "domain '{}' on appliance '{}' "
                        "needs to be saved. Use force option "
                        "to deploy anyway".format(appliance.hostname, app_domain)
                    )
            ret.extend(self.get_predeployment_steps(appliance, app_domain))
            ret.extend(self.get_deployment_steps(appliance, app_domain))
        return ret


    def get_deployment_steps(self, appliance, app_domain):
        project_root = self.config["repo_dir"]

        env_dir = os.path.join(project_root, self.config["environment"])
        env_config_dir = os.path.join(env_dir, "config")
        env_local_dir = os.path.join(env_dir, "local")
        env_cert_dir = os.path.join(env_dir, "cert")
        env_sharedcert_dir = os.path.join(env_dir, "sharedcert")
        env_pubcert_dir = os.path.join(env_dir, "pubcert")
        env_deppol_dir = os.path.join(env_dir, "DeploymentPolicy")
        env_password_alias_file = os.path.join(env_dir, "password", "alias-password.map")
        common_config_dir = os.path.join(project_root, "config")
        common_local_dir = os.path.join(project_root, "local")
        common_cert_dir = os.path.join(project_root, "cert")
        common_sharedcert_dir = os.path.join(project_root, "sharedcert")
        common_pubcert_dir = os.path.join(project_root, "pubcert")
        common_password_alias_file = os.path.join(project_root, "password", "alias-password.map")

        ret = []
        tmpl = appliance.hostname + "-{}-{}"
        deployment_policy = None
        filestore = appliance.get_filestore(app_domain)
        services = []

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
        if exists(common_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_pubcert_dir)):
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-set-file".format(appliance.hostname),
                        appliance.set_file,
                        domain="default",
                        file_in=os.path.join(common_pubcert_dir, filename),
                        file_out="pubcert:///{}".format(filename),
                    )
                ])
        if exists(common_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_cert_dir)):
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-set-file".format(appliance.hostname),
                        appliance.set_file,
                        domain=app_domain,
                        file_in=os.path.join(common_cert_dir, filename),
                        file_out="cert:///{}".format(filename),
                    )
                ])
        if exists(common_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_sharedcert_dir)):
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-set-file".format(appliance.hostname),
                        appliance.set_file,
                        domain="default",
                        file_in=os.path.join(common_sharedcert_dir, filename),
                        file_out="sharedcert:///{}".format(filename),
                    )
                ])
        if exists(env_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_pubcert_dir)):
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-set-file".format(appliance.hostname),
                        appliance.set_file,
                        domain="default",
                        file_in=os.path.join(env_pubcert_dir, filename),
                        file_out="pubcert:///{}".format(filename),
                    )
                ])
        if exists(env_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_cert_dir)):
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-set-file".format(appliance.hostname),
                        appliance.set_file,
                        domain=app_domain,
                        file_in=os.path.join(env_cert_dir, filename),
                        file_out="cert:///{}".format(filename),
                    )
                ])
        if exists(env_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_sharedcert_dir)):
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-set-file".format(appliance.hostname),
                        appliance.set_file,
                        domain="default",
                        file_in=os.path.join(env_sharedcert_dir, filename),
                        file_out="sharedcert:///{}".format(filename),
                    )
                ])
        if exists(common_local_dir):
            for root, dirs, files in os.walk(common_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(common_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        target_dir = "/".join(file_out.split("/")[:-1])
                        if not appliance.directory_exists(target_dir, app_domain, filestore):
                            ret.append(
                                Action(
                                    appliance,
                                    self.config,
                                    "{}-CreateDir".format(appliance.hostname),
                                    appliance.CreateDir,
                                    domain=app_domain,
                                    Dir=target_dir
                                )
                            )
                        ret.append(
                            Action(
                                appliance,
                                self.config,
                                "{}-set-file".format(appliance.hostname),
                                appliance.set_file,
                                domain=app_domain,
                                file_in=os.path.join(root, filename),
                                file_out=file_out
                            )
                        )
        if exists(env_local_dir):
            for root, dirs, files in os.walk(env_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(env_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        target_dir = "/".join(file_out.split("/")[:-1])
                        if not appliance.directory_exists(target_dir, app_domain, filestore):
                            ret.append(
                                Action(
                                    appliance,
                                    self.config,
                                    "{}-CreateDir".format(appliance.hostname),
                                    appliance.CreateDir,
                                    domain=app_domain,
                                    Dir=target_dir
                                )
                            )
                        ret.append(
                            Action(
                                appliance,
                                self.config,
                                "{}-set-file".format(appliance.hostname),
                                appliance.set_file,
                                domain=app_domain,
                                file_in=os.path.join(root, filename),
                                file_out=file_out
                            )
                        )
        if exists(env_deppol_dir):
            if len(filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))) > 1:
                raise ValueError("Only one deployment policy permitted.")
            deployment_policy_filename = filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))[0]
            deployment_policy_filename = os.path.join(env_deppol_dir, deployment_policy_filename)
            tree = etree.parse(deployment_policy_filename)
            deployment_policy = tree.find(".//ConfigDeploymentPolicy").get("name")
            ret.extend([
                Action(
                    appliance,
                    self.config,
                    "{}-import".format(appliance.hostname),
                    appliance.do_import,
                    domain=app_domain,
                    zip_file=os.path.join(env_deppol_dir, filename),
                    source_type="XML"
                )
                for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))
            ])
        if exists(common_password_alias_file):
            with open(common_password_alias_file, "r") as fp:
                for line in fp:
                    name, password = line.split(":")
                    ret.extend([
                        Action(
                            appliance,
                            self.config,
                            "{}-AddPasswordMap".format(appliance.hostname),
                            appliance.AddPasswordMap,
                            domain=app_domain,
                            AliasName=name.strip(),
                            Password=password.strip()
                        )
                    ])
        if exists(env_password_alias_file):
            with open(env_password_alias_file, "r") as fp:
                for line in fp:
                    name, password = line.split(":")
                    ret.extend([
                        Action(
                            appliance,
                            self.config,
                            "{}-AddPasswordMap".format(appliance.hostname),
                            appliance.AddPasswordMap,
                            domain=app_domain,
                            AliasName=name.strip(),
                            Password=password.strip()
                        )
                    ])
        if exists(common_config_dir):
            if self.config["quiesce"]:
                for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_config_dir)):
                    _filename = os.path.join(common_config_dir, filename)
                    tree = etree.parse(_filename)
                    for obj in tree.findall(r'.//configuration/*'):
                        if obj.tag in DATAPOWER_SERVICE_TYPES:
                            services.append(obj)
                            ret.insert(
                                1,
                                Action(
                                    appliance,
                                    self.config,
                                    "{}-quiesce".format(appliance.hostname),
                                    appliance.ServiceQuiesce,
                                    domain=app_domain,
                                    type=obj.tag,
                                    name=obj.get("name"),
                                    timeout=self.config["quiesce_timeout"],
                                    delay=self.config["quiesce_delay"],
                                )
                            )
            if not self.config["force"]:
                quit_for_local_uploads(common_config_dir)
            if deployment_policy:
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-import".format(appliance.hostname),
                        appliance.do_import,
                        domain=app_domain,
                        deployment_policy=deployment_policy,
                        zip_file=os.path.join(common_config_dir, filename),
                        source_type="XML"
                    )
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_config_dir))
                ])
            else:
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-import".format(appliance.hostname),
                        appliance.do_import,
                        domain=app_domain,
                        zip_file=os.path.join(common_config_dir, filename),
                        source_type="XML"
                    )
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_config_dir))
                ])
        if exists(env_config_dir):
            if self.config["quiesce"]:
                for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_config_dir)):
                    _filename = os.path.join(env_config_dir, filename)
                    tree = etree.parse(_filename)
                    for obj in tree.findall(r'.//configuration/*'):
                        if obj.tag in DATAPOWER_SERVICE_TYPES:
                            services.append(obj)
                            ret.insert(
                                1,
                                Action(
                                    appliance,
                                    self.config,
                                    "{}-quiesce".format(appliance.hostname),
                                    appliance.ServiceQuiesce,
                                    domain=app_domain,
                                    type=obj.tag,
                                    name=obj.get("name"),
                                    timeout=self.config["quiesce_timeout"],
                                    delay=self.config["quiesce_delay"],
                                )
                            )
            if not self.config["force"]:
                quit_for_local_uploads(env_config_dir)
            if deployment_policy:
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-import".format(appliance.hostname),
                        appliance.do_import,
                        domain=app_domain,
                        deployment_policy=deployment_policy,
                        zip_file=os.path.join(env_config_dir, filename),
                        source_type="XML"
                    )
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_config_dir))
                ])
            else:
                ret.extend([
                    Action(
                        appliance,
                        self.config,
                        "{}-import".format(appliance.hostname),
                        appliance.do_import,
                        domain=app_domain,
                        zip_file=os.path.join(env_config_dir, filename),
                        source_type="XML"
                    )
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_config_dir))
                ])

        if services:
            for service in services:
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-unquiesce".format(appliance.hostname),
                        appliance.ServiceUnquiesce,
                        domain=app_domain,
                        type=service.tag,
                        name=service.get("name"),
                    )
                )
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


    def get_predeployment_steps(self, appliance, app_domain):
        """Predeployment now consiste of a checkpoint and normal backup
        in the default domain and the app domain.
        """
        tmpl = appliance.hostname + "-{}-{}"
        ret = []
        for domain in [app_domain, "default"]:
            if len(appliance.get_existing_checkpoints(domain)) == appliance.max_checkpoints(domain):
                ret.append(
                    Action(
                        appliance,
                        self.config,
                        "{}-remove-oldest-checkpoint".format(appliance.hostname),
                        appliance.remove_oldest_checkpoint,
                        domain=domain,
                    )
                )
        ret.extend([
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
            ),
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
            ),
            Action(
                appliance,
                self.config,
                "{}-NormalBackup".format(appliance.hostname),
                appliance.get_normal_backup,
                domains="default"
            ),
            Action(
                appliance,
                self.config,
                "{}-NormalBackup".format(appliance.hostname),
                appliance.get_normal_backup,
                domains=app_domain
            ),
        ])
        return ret

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
        if "save-config" in self.name:
            filename = os.path.join(self.config["audit_dir"], "{}.xml".format(self.appliance.hostname))
            log.info(
                "auditing configuration changes for '{}', "
                "results can be found in '{}'".format(
                    self.appliance.hostname, filename
                )
            )
            with open(filename, "w") as fp:
                fp.write(self.appliance.object_audit())

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
        with open(req_file, "w") as fp:
            fp.write(str(self.appliance.request))
        with open(resp_file, "w") as fp:
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
        return "{}({})".format(self.name, ", ".join(
            [
                "{}={}".format(k, repr(v)) for k, v in self.kwargs.items() if "password" not in k.lower()
            ]
        ))

def parse_config(config, appliances, credentials, environment, service):
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
    return ret


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
        force=False,
        quiesce=True,
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
* `-f, --force`: If specified, deployment will proceed regardless of whether
the app domain needs to be saved and regardless of whether there are local
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
    if web:
        output = OrderedDict()
    config = get_config("service-config.conf")
    # filter (and merge) configuration to that which is applicable to this deployment
    config = parse_config(config, appliances, credentials, environment, service)

    if not out_dir:
        out_dir = os.path.join(os.environ["MAST_HOME"], "tmp", "deployment-results")
    audit_dir = os.path.join(out_dir, "audit")
    if not os.path.exists(audit_dir):
        os.makedirs(audit_dir)
    handler = logging.FileHandler(
        os.path.join(
            out_dir,
            "deployment.log"
        ),
        "w"
    )
    formatter = logging.Formatter(
        "%(asctime)s: %(levelname)s: %(relativeCreated)d: %(message)s"
    )
    handler.setFormatter(formatter)
    log.addHandler(handler)
    repo_dir = os.path.join(out_dir, service)
    config["audit_dir"] = audit_dir
    config["out_dir"] = out_dir
    config["repo_dir"] = repo_dir
    config["force"] = force
    config["quiesce"] = quiesce
    config["quiesce_delay"] = quiesce_delay
    config["quiesce_timeout"] = quiesce_timeout
    config["save_config"] = save_config
    config["step_number"] = 0
    if "subdirectory" in config:
        config["repo_dir"] = os.path.join(config["repo_dir"], config["subdirectory"])
    if "git-credentials" in config:
        username, password = xordecode(config["git-credentials"]).split(":")
        url = urlparse(config["repo"])
        config["repo"] = "{}://{}:{}@{}{}".format(
            url.scheme,
            quote_plus(username),
            quote_plus(password),
            url.netloc,
            url.path,
        )
    if exists(repo_dir):
        log.info("Existing local repository found, pulling latest changes")
        with working_directory(repo_dir):
            out, err = system_call("git pull")
    else:
        log.info("cloning repo '{}' to '{}'".format(config["repo"], repo_dir))
        out, err = system_call("git clone {} {}".format(config["repo"], repo_dir))
    if not web:
        print(out if out else "")
        print(err if err else "")
    if commit:
        with working_directory(repo_dir):
            log.info("performing 'git checkout {}'".format(commit))
            out, err = system_call("git checkout {}".format(commit))
        if not web:
            print(out if out else "")
            print(err if err else "")

    environment = datapower.Environment(
        config["appliances"],
        credentials=config["credentials"],
        check_hostname=not no_check_hostname,
        timeout=timeout
    )
    plan = Plan(config, environment, service)
    if not os.path.exists(out_dir):
        log.info("'{}' does not exist, creating...".format(out_dir))
        os.makedirs(out_dir)
    with open(os.path.join(out_dir, "plan.txt"), "w") as fp:
        for index, action in enumerate(plan):
            fp.write("Step {}, {}{}".format(index, action.name, os.linesep))
            for k, v in action.kwargs.items():
                fp.write("\t{}={}{}".format(k, v, os.linesep))
    for index, action in enumerate(plan):
        if web:
            output["{}-{}".format(index, action.name)] = str(action)
        else:
            print("Step {}, {}".format(index, action.name))
            for k, v in action.kwargs.items():
                print("\t{}={}".format(k, v))
        if dry_run:
            continue
        log.info("Executing action '{}'".format(repr(action)))
        _output = action()
        if "CreateDir" in action.name:
            sleep(5)
        if "quiesce" in action.name and "unquiesce" not in action.name:
            sleep(config["quiesce_timeout"] + config["quiesce_delay"])
    if web:
        return render_results_table(output), render_history(environment)

if __name__ == "__main__":
    cli = Cli(main=main, description=main.__doc__)
    try:
        cli.run()
    except SystemExit:
        pass
    except:
        make_logger("error").exception("An unhandled exception occurred")
        raise
