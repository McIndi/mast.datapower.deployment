from mast.datapower import datapower
from mast.logging import make_logger
from mast.config import get_config
from mast.xor import xorencode
from subprocess import Popen
from mast.timestamp import Timestamp
from mast.cli import Cli
from time import sleep
from functools import partial
import os


def exists(path):
    return os.path.exists(path)

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
            ret.extend(self.get_predeployment_steps(appliance, app_domain))
            ret.extend(self.get_deployment_steps(appliance, app_domain))
        return ret


    def get_deployment_steps(self, appliance, app_domain):
        project_root = os.path.join(self.config["repo"], self.config["root"])
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

        if exists(env_dir):
            if exists(env_password_alias_file):
                with open(env_password_alias_file, "r") as fp:
                    for line in fp:
                        name, password = line.split(":")
                        ret.extend([
                            Action("{}-AddPasswordMap".format(appliance.hostname),
                                   appliance.AddPasswordMap,
                                   domain=app_domain,
                                   AliasName=name.strip(),
                                   Password=password.strip())
                        ])
            if exists(env_deppol_dir):
                if len(filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))) > 1:
                    raise ValueError("Only one deployment policy permitted.")
                ret.extend([
                    Action("{}-import".format(appliance.hostname),
                           appliance.do_import,
                           domain=app_domain,
                           zip_file=os.path.join(env_deppol_dir, filename),
                           source_type="XML")
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))
                ])
                deployment_policy = filter(lambda x: "EMPTY" not in x, os.listdir(env_deppol_dir))[0]
                deployment_policy = ".".join(deployment_policy.split(".")[:-1])
            if exists(env_cert_dir):
                for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_cert_dir)):
                    ret.extend([
                        Action("{}-set-file".format(appliance.hostname),
                               appliance.set_file,
                               domain=app_domain,
                               file_in=os.path.join(env_cert_dir, filename),
                               file_out="cert:///{}".format(filename),
                        )
                    ])
            if exists(env_pubcert_dir):
                for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_pubcert_dir)):
                    ret.extend([
                        Action("{}-set-file".format(appliance.hostname),
                               appliance.set_file,
                               domain="default",
                               file_in=os.path.join(env_pubcert_dir, filename),
                               file_out="pubcert:///{}".format(filename),
                        )
                    ])
            if exists(env_sharedcert_dir):
                for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_sharedcert_dir)):
                    ret.extend([
                        Action("{}-set-file".format(appliance.hostname),
                               appliance.set_file,
                               domain="default",
                               file_in=os.path.join(env_sharedcert_dir, filename),
                               file_out="sharedcert:///{}".format(filename),
                        )
                    ])
            if exists(env_local_dir):
                for root, dirs, files in os.walk(env_local_dir):
                    if files:
                        for filename in filter(lambda x: "EMPTY" not in x, files):
                            file_out = "local://{}".format(os.path.join(root, filename))
                            file_out = file_out.replace(env_local_dir, "")
                            file_out = file_out.replace(os.path.sep, "/")
                            target_dir = "/".join(file_out.split("/")[:-1])
                            ret.append(Action("{}-CreateDir".format(appliance.hostname),
                                              appliance.CreateDir,
                                              Dir=target_dir))
                            ret.append(Action("{}-set-file".format(appliance.hostname),
                                              appliance.set_file,
                                              domain=app_domain,
                                              file_in=os.path.join(root, filename),
                                              file_out=file_out))
            if exists(env_config_dir):
                if deployment_policy:
                    ret.extend([
                        Action("{}-import".format(appliance.hostname),
                               appliance.do_import,
                               domain=app_domain,
                               deployment_policy=deployment_policy,
                               zip_file=os.path.join(env_config_dir, filename),
                               source_type="XML")
                        for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_config_dir))
                    ])
                else:
                    ret.extend([
                        Action("{}-import".format(appliance.hostname),
                               appliance.do_import,
                               domain=app_domain,
                               zip_file=os.path.join(env_config_dir, filename),
                               source_type="XML")
                        for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_config_dir))
                    ])
        if exists(common_password_alias_file):
            with open(common_password_alias_file, "r") as fp:
                for line in fp:
                    name, password = line.split(":")
                    ret.extend([
                        Action("{}-AddPasswordMap".format(appliance.hostname),
                               appliance.AddPasswordMap,
                               domain=app_domain,
                               AliasName=name.strip(),
                               Password=password.strip())
                    ])
        if exists(common_local_dir):
            for root, dirs, files in os.walk(common_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(common_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        target_dir = "/".join(file_out.split("/")[:-1])
                        ret.append(Action("{}-CreateDir".format(appliance.hostname),
                                          appliance.CreateDir,
                                          Dir=target_dir))
                        ret.append(Action("{}-set-file".format(appliance.hostname),
                                          appliance.set_file,
                                          domain=app_domain,
                                          file_in=os.path.join(root, filename),
                                          file_out=file_out))
        if exists(common_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_cert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain=app_domain,
                           file_in=os.path.join(common_cert_dir, filename),
                           file_out="cert:///{}".format(filename),
                    )
                ])
        if exists(common_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_pubcert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain="default",
                           file_in=os.path.join(common_pubcert_dir, filename),
                           file_out="pubcert:///{}".format(filename),
                    )
                ])
        if exists(common_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_sharedcert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain="default",
                           file_in=os.path.join(common_sharedcert_dir, filename),
                           file_out="sharedcert:///{}".format(filename),
                    )
                ])
        if exists(common_config_dir):
            if deployment_policy:
                ret.extend([
                    Action("{}-import".format(appliance.hostname),
                           appliance.do_import,
                           domain=app_domain,
                           deployment_policy=deployment_policy,
                           zip_file=os.path.join(common_config_dir, filename),
                           source_type="XML")
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_config_dir))
                ])
            else:
                ret.extend([
                    Action("{}-import".format(appliance.hostname),
                           appliance.do_import,
                           domain=app_domain,
                           zip_file=os.path.join(common_config_dir, filename),
                           source_type="XML")
                    for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_config_dir))
                ])
        if exists(common_local_dir):
            for root, dirs, files in os.walk(common_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(common_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        target_dir = "/".join(file_out.split("/")[:-1])
                        ret.append(Action("{}-CreateDir".format(appliance.hostname),
                                          appliance.CreateDir,
                                          Dir=target_dir))
                        ret.append(Action("{}-set-file".format(appliance.hostname),
                                          appliance.set_file,
                                          domain=app_domain,
                                          file_in=os.path.join(root, filename),
                                          file_out=file_out))

        if exists(common_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_cert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain=app_domain,
                           file_in=os.path.join(common_cert_dir, filename),
                           file_out="cert:///{}".format(filename),
                    )
                ])
        if exists(common_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_pubcert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain="default",
                           file_in=os.path.join(common_pubcert_dir, filename),
                           file_out="pubcert:///{}".format(filename),
                    )
                ])
        if exists(common_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(common_sharedcert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain="default",
                           file_in=os.path.join(common_sharedcert_dir, filename),
                           file_out="sharedcert:///{}".format(filename),
                    )
                ])
        if exists(env_cert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_cert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain=app_domain,
                           file_in=os.path.join(env_cert_dir, filename),
                           file_out="cert:///{}".format(filename),
                    )
                ])
        if exists(env_pubcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_pubcert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain="default",
                           file_in=os.path.join(env_pubcert_dir, filename),
                           file_out="pubcert:///{}".format(filename),
                    )
                ])
        if exists(env_sharedcert_dir):
            for filename in filter(lambda x: "EMPTY" not in x, os.listdir(env_sharedcert_dir)):
                ret.extend([
                    Action("{}-set-file".format(appliance.hostname),
                           appliance.set_file,
                           domain="default",
                           file_in=os.path.join(env_sharedcert_dir, filename),
                           file_out="sharedcert:///{}".format(filename),
                    )
                ])
        if exists(env_local_dir):
            for root, dirs, files in os.walk(env_local_dir):
                if files:
                    for filename in filter(lambda x: "EMPTY" not in x, files):
                        file_out = "local://{}".format(os.path.join(root, filename))
                        file_out = file_out.replace(env_local_dir, "")
                        file_out = file_out.replace(os.path.sep, "/")
                        target_dir = "/".join(file_out.split("/")[:-1])
                        ret.append(Action("{}-CreateDir".format(appliance.hostname),
                                          appliance.CreateDir,
                                          Dir=target_dir))
                        ret.append(Action("{}-set-file".format(appliance.hostname),
                                          appliance.set_file,
                                          domain=app_domain,
                                          file_in=os.path.join(root, filename),
                                          file_out=file_out))
        return ret


    def get_predeployment_steps(self, appliance, app_domain):
        """Predeployment now consiste of a checkpoint and normal backup
        in the default domain and the app domain.
        """
        tmpl = appliance.hostname + "-{}-{}"
        return [
            Action("{}-SaveCheckpoint".format(appliance.hostname), appliance.SaveCheckpoint, domain="default", ChkName="{}_{}".format("default", Timestamp().epoch)),
            Action("{}-SaveCheckpoint".format(appliance.hostname), appliance.SaveCheckpoint, domain=app_domain, ChkName="{}_{}".format(app_domain, Timestamp().epoch)),
            Action("{}-NormalBackup".format(appliance.hostname), appliance.get_normal_backup, domains="default"),
            Action("{}-NormalBackup".format(appliance.hostname), appliance.get_normal_backup, domains=app_domain),
        ]

class Action(object):
    """A class representing a action to be taken as
    part of a deployment.

    This is a fairly simple wrapper around
    ``functools.partial()``. It is a callable
    action which executes a function, but there
    is some more features which are designed to
    allow easy construction of plans
    """
    def __init__(self, *args, **kwargs):
        self.name = args[0]
        self.args = args
        self.kwargs = kwargs
        self.callable = partial(args[1], *args[2:], **kwargs)

    def __call__(self):
        return self.callable()

    def __repr__(self):
        return "<Action " + self.name + "({})>".format(", ".join(["{}={}".format(k, repr(v)) for k, v in self.kwargs.items()]))

def parse_config(config, environment, service):
    ret = {}
    ret["appliances"] = config.get(service, "environment-{}".format(environment)).split()
    ret["domains"] = [v.split(":")[1] for v in ret["appliances"]]
    ret["appliances"] = [v.split(":")[0] for v in ret["appliances"]]
    ret["environment"] = environment
    ret.update(config.items("global"))
    ret.update(config.items(service))
    return ret


def git_deploy(environment="", service="", credentials=[], out_dir="", timeout=120, dry_run=False):
    """
    Deploy services to IBM DataPower appliances. See
    https://mcindi.github.io/mast/deploy.html for details
    on how to configure and use this script.
    """
    config = get_config("service-config.conf")
    # filter (and merge) configuration to that which is applicable to this deployment
    config = parse_config(config, environment, service)

    if not out_dir:
        out_dir = os.path.join(config["repo"], config["root"], "deployment-results")
    environment = datapower.Environment(config["appliances"],
                                        credentials=credentials,
                                        check_hostname=False,
                                        timeout=timeout)
    plan = Plan(config, environment, service)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    for index, action in enumerate(plan):
        print(action)
        if dry_run:
            continue
        filename = os.path.join(out_dir, "{}-{}.xml".format(index, action.name))
        output = action()
        if "NormalBackup" in action.name:
            filename = filename.replace(".xml", ".zip")
        print("<Results '{}'>\n".format(filename))
        with open(filename, "wb") as fp:
            try:
                fp.write(output)
            except TypeError:
                fp.write(str(output))
        if "CreateDir" in action.name:
            sleep(5)


if __name__ == "__main__":
    cli = Cli(main=main, description=main.__doc__)
    try:
        cli.run()
    except SystemExit:
        pass
    except:
        make_logger("error").exception("An unhandled exception occurred")
        raise
