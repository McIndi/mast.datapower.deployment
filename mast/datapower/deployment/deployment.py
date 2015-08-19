# -*- coding: utf-8 -*-
from mast.datapower import datapower
import mast.plugin_utils.plugin_utils as util
from mast.timestamp import Timestamp
from time import sleep
from mast.logging import make_logger, logged
import commandr
import flask
import sys
import os

logger = make_logger('mast.datapower.deployment')

cli = commandr.Commandr()


@logged('mast.datapower.deployment')
@cli.command('set-file', category='file management')
def set_file(appliances=[], credentials=[], timeout=120,
             file_in=None, destination=None, Domain='default',
             overwrite=True, no_check_hostname=False, web=False):
    """Uploads a file to the specified appliances

Parameters:

file-in - The path and filename of the file to upload
* destination - Should be the path and filename of the file
once uploaded to the DataPower **NOTE: file_out should contain
the filename ie. local:/test.txt**
* Domain - The domain to which to upload the file"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    kwargs = {
        'file_in': file_in,
        'file_out': destination,
        'domain': Domain,
        'overwrite': overwrite}
    resp = env.perform_async_action('set_file', **kwargs)

    if web:
        return util.render_boolean_results_table(
            resp, suffix="set_file"), util.render_history(env)


@logged('mast.datapower.deployment')
@cli.command('get-file', category='file management')
def get_file(appliances=[], credentials=[], timeout=120,
             location=None, Domain='default', out_dir='tmp', no_check_hostname=False, web=False):
    """Uploads a file to the specified appliances

Parameters:

* location - The location of the file (on DataPower) you would
like to get
* Domain - The domain from which to get the file
* out-dir - (NOT NEEDED IN THE WEB GUI)The directory you would like to
save the file to"""

    t = Timestamp()
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    kwargs = {'domain': Domain, 'filename': location}
    responses = env.perform_async_action('getfile', **kwargs)

    if not os.path.exists(out_dir) or not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    for hostname, fin in list(responses.items()):
        filename = location.split('/')[-1]
        filename = os.path.join(
            out_dir,
            '%s-%s-%s' % (hostname, t.timestamp, filename))
        with open(filename, 'wb') as fout:
            fout.write(fin)
    if web:
        return util.render_see_download_table(
            responses, suffix="get_file"), util.render_history(env)


@logged('mast.datapower.deployment')
@cli.command('del_file', category="file management")
def delete_file(appliances=[], credentials=[], timeout=120,
    Domain="", filename="", backup=False, out_dir="tmp",
    no_check_hostname=False, web=False):
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    if backup:
        resp = {}
        for appliance in env.appliances:
            _out_dir = os.path.join(out_dir, appliance.hostname)
            if not os.path.exists(_out_dir):
                os.makedirs(_out_dir)
            resp[appliance.hostname] = appliance.del_file(
                filename=filename, domain=Domain,
                backup=True, local_dir=_out_dir)
    else:
        resp = env.perform_action("del_file", filename=filename, domain=Domain)
    if web:
        return util.render_boolean_results_table(resp), util.render_history(env)
    for host, response in resp.items():
        print host
        print "=" * len(host)
        if response:
            print "Success"
        else:
            print "Error"
        print


@logged('mast.datapower.deployment')
@cli.command('clean-up', category='maintenance')
def clean_up(appliances=[], credentials=[],
             Domain='default', checkpoints=False,
             export=False, error_reports=False,
             recursive=False, logtemp=False,
             logstore=False, backup_files=True,
             timeout=120, out_dir='tmp', no_check_hostname=False, web=False):
    """This will clean up the specified appliances filesystem.

Parameters:

* Domain - The domain who's filesystem you would like to clean up
* checkpoints - Whether to cleanup the checkpoints: directory
* export - Whether to clean up the export directory
* logtemp - Whether to clean up the logtemp: directory
* logstore - Whether to clean up the logstore directory
* error-reports - Whether to clean up the error reports
* recursive - Whether to recurse through sub-directories
* backup_files - Whether to backup files before deleting them"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    t = Timestamp()
    dirs = []
    if checkpoints:
        dirs.append('chkpoints:/')
    if export:
        dirs.append('export:/')
    if logtemp:
        dirs.append('logtemp:/')
    if logstore:
        dirs.append('logstore:/')

    if web:
        rows = []
    for appliance in env.appliances:
        if web:
            rows.append((appliance.hostname, ))
        for _dir in dirs:
            _clean_dir(
                appliance,
                _dir,
                Domain,
                recursive,
                backup_files,
                t.timestamp,
                out_dir)
            if web:
                rows.append(("", _dir, "Cleaned"))
        if error_reports:
            _clean_error_reports(
                appliance, Domain,
                backup_files, t.timestamp,
                out_dir)
            rows.append(("", "ErrorReports", "Cleaned"))
    return flask.render_template(
        "results_table.html",
        header_row=["Appliance", "Location", "Action"],
        rows=rows), util.render_history(env)


@logged('mast.datapower.deployment')
def _clean_dir(appliance, _dir, domain, recursive, backup, timestamp, out_dir):
    if backup:
        local_dir = os.path.sep.join(
            os.path.sep.join(_dir.split(':/')).split('/'))
        local_dir = os.path.join(
            out_dir,
            appliance.hostname,
            timestamp,
            domain,
            local_dir)
        os.makedirs(local_dir)
    # if not recursive don't include_directories
    files = appliance.ls(_dir, domain=domain, include_directories=recursive)
    for file in files:
        if ':/' in file:
            _clean_dir(
                appliance,
                file,
                domain,
                recursive,
                backup,
                timestamp,
                out_dir)
        else:
            filename = '{}/{}'.format(_dir, file)
            if backup:
                fout = open(os.path.join(local_dir, file), 'wb')
                contents = appliance.getfile(domain, filename)
                fout.write(contents)
                fout.close
            appliance.DeleteFile(domain=domain, File=filename)


@logged('mast.datapower.deployment')
def _clean_error_reports(appliance, domain, backup, timestamp, out_dir):
    if backup:
        local_dir = os.path.join(
            out_dir,
            appliance.hostname,
            timestamp,
            domain,
            'temporary')
        os.makedirs(local_dir)
    files = appliance.ls(
        'temporary:/',
        domain=domain,
        include_directories=False)
    files = [f for f in files if 'error-report' in f]
    for _file in files:
        filename = 'temporary:/{}'.format(_file)
        if backup:
            fout = open(os.path.join(local_dir, _file), 'wb')
            contents = appliance.getfile(domain, filename)
            fout.write(contents)
            fout.close
        appliance.DeleteFile(domain=domain, File=filename)


@logged('mast.datapower.deployment')
@cli.command('predeploy', category='deployment')
def predeploy(
    appliances=[],
    credentials=[],
    timeout=120,
    out_dir="tmp",
    Domain="",
    comment="",
    CryptoCertificate="",
    secure_backup_destination="local:/raid0",
    backup_default=True,
    backup_all=True,
    do_secure_backup=False,
    do_normal_backup=True,
    set_checkpoints=True,
    include_iscsi=False,
    include_raid=False,
    remove_secure_backup=True,
    web=False,
    default_checkpoint=True,
    remove_oldest_checkpoint=True,
    no_check_hostname=False):
    """Perform routine pre-deployment actions. Everything is optional, but if
   you wish to perform an action, you must provide the necessary arguments.

   Here is what is possible (will be done in this order):

   1. Secure Backup
     * The following params must be specified:
        * do_secure_backup - Whether to retrieve a secure backup

        * out_dir (not needed in web GUI) - The directory (local) where
        the secure backup will be stored

        * CryptoCertificate - The CryptoCertificate with which to
        encrypt the secure backup

        * secure_backup_destination - The destination (on the DataPower)
        where the secure backup will be stored

        * include_iscsi - Whether to include the iscsi volume in the
        secure backup

        * include_raid - Whether to include the raid volume in the
        secure backup

        * remove_secure_backup - Whether to remove the secure backup
        from the appliance after verifying your local copy.

   2. Normal Backups
      * The following params must be specified:
         * do_normal_backup - Whether to retrieve normal backups

         * out_dir - (Not needed in web GUI)

         * Domain - This is shared among other actions. This is the app
         domain to backup. This is meant to be the domain to which
         the deployment is going.

         * backup_default - Whether to also backup the default domain

         * backup_all - Whether to also backup all-domains

         * comment - This is shared among other actions. The comment to
         include in the normal backups.

   3. Checkpoints
     * The following params must be specified:
        * set_checkpoints - Whether to set checkpoints

        * Domain - This is shared among other actions. This is the app
        domain in which to set a checkpoint. This is meant to be the
        domain to which the deployment is going.

        * comment - This is shared among other actions. The comment is
        used to build the name of the checkpoint.

        * default_checkpoint - Whether to create a checkpoint in the
        default domain

        * remove_oldest_checkpoint - Whether to remove the oldest
        checkpoint from the domain IF AND ONLY IF the maximum number
        of checkpoints has been reached."""
    if web:
        from mast.backups import set_checkpoint, get_normal_backup, get_secure_backup
        import mast.system as system
    else:
        #lint:disable
        from mast.backups import set_checkpoint
        from mast.backups import get_normal_backup, get_secure_backup
        import mast.system as system
        #lint:enable

    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    if web:
        output = ""
        history = ""

    # Loop through appliances so we will only affect one appliance at a time
    for appliance in env.appliances:

        # Secure Backup
        if do_secure_backup:
            if not CryptoCertificate:
                # Fail if CryptoCertificate is not given
                logger.error(
                    "Cert must be specified in order "
                    "to perform a secure backup!")
                sys.exit(-1)

            logger.info("Starting Secure Backup for {}".format(
                appliance.hostname))

            resp, hist = get_secure_backup(
                appliances=appliance.hostname,
                credentials=appliance.credentials,
                timeout=timeout,
                out_dir=out_dir,
                CryptoCertificate=CryptoCertificate,
                destination=secure_backup_destination,
                include_iscsi=include_iscsi,
                include_raid=include_raid,
                remove=remove_secure_backup,
                quiesce_before=False,
                unquiesce_after=False,
                no_check_hostname=no_check_hostname,
                web=web)

            if web:
                output += resp
                history += hist

            logger.info("Finished Secure Backup for {}".format(
                appliance.hostname))

        # Normal backups
        if do_normal_backup:
            logger.info(
                "Pre-Deployment backups started at {}".format(
                    str(Timestamp())))

            domains = [Domain]
            if backup_default:
                domains.append("default")
            if backup_all:
                domains.append("all-domains")

            resp, hist = get_normal_backup(
                appliance.hostname,
                credentials,
                timeout,
                domains,
                comment,
                out_dir,
                no_check_hostname=no_check_hostname,
                web=web)

            logger.info(
                "Pre-Deployment backups finished at {}".format(
                    str(Timestamp())))

            if web:
                output += resp
                history += hist

        # Checkpoints
        if set_checkpoints:
            logger.info(
                "Pre-Deployment checkpoints started at {}".format(
                    str(Timestamp())))

            domains = [Domain]
            if default_checkpoint:
                domains.append("default")

            resp, hist = set_checkpoint(
                appliance.hostname,
                credentials,
                timeout,
                domains,
                comment,
                remove_oldest_checkpoint,
                no_check_hostname=no_check_hostname,
                web=web)

            logger.info(
                "Pre-Deployment checkpoints finished at {}".format(
                    str(Timestamp())))

            if web:
                output += resp
                history += hist

        ## Quiesce Domain
        #if quiesce_domain:
            #logger.info(
                #"Quiescing domain {} before deployment at {}".format(
                    #Domain, str(Timestamp())))

            #resp, hist = system.quiesce_domain(
                #appliance.hostname,
                #credentials,
                #timeout,
                #Domain,
                #quiesce_timeout,
                #web=web)

            #logger.info(
                #"Finished quiescing domain {} before deployment at {}".format(
                    #Domain, str(Timestamp())))

            #sleep(quiesce_timeout)

            #if web:
                #output += resp
                #history += hist

        ## Quiesce Appliance
        #if quiesce_appliance:
            #logger.info(
                #"Quiescing appliances before deployment at {}".format(
                    #str(Timestamp())))

            #resp, hist = system.quiesce_appliance(
                #appliance.hostname,
                #credentials,
                #timeout,
                #quiesce_timeout,
                #web=web)

            #logger.info(
                #"Finished quiescing appliances before deployment at {}".format(
                    #str(Timestamp())))

            #sleep(quiesce_timeout)

            #if web:
                #output += resp
                #history += hist

    if web:
        return output, history


@logged('mast.datapower.deployment')
@cli.command('deploy', category='deployment')
def deploy(
    appliances=[],
    credentials=[],
    Domain="",
    file_in=None,
    deployment_policy="",
    dry_run=False,
    overwrite_files=True,
    overwrite_objects=True,
    rewrite_local_ip=True,
    object_audit=True,
    out_dir='tmp',
    format='ZIP',
    predeploy_command=None,
    postdeploy_command=None,
    quiesce_domain=True,
    quiesce_appliance=False,
    quiesce_timeout=120,
    timeout=180,
    no_check_hostname=False, web=False):

    """Perform a deployment/migration of a service/object to an IBM DataPower
   appliance. This script will try to perform the deployment/migration in a
   manner consistent with best practices.

   WARNING: There is an inherent security risk involved in this script,
            in order to allow the most flexible integration with various
            Version Control Systems possible, we allow a pre-deployment
            hook and a post-deployment hook which will be "shelled out"
            to your operating system. For this reason PLEASE be sure to
            run this script (and the MAST Web GUI server) as a user with
            appropriate permissions.

   DO NOT RUN AS ROOT!!!

   You can perform the following options with this script:

   * predeploy_command:

      * This is a command which will be issued to your underlying OS
      before the deployment/migration is performed.
      This is provided for the purpose of integrating with you VCS,
      It will allow you to checkout/clone your new/updated
      service/object from the latest possible sources.

      * It is advised to wrap these commands in shell or batch
      scripts and call them so that the same actions are performed
      each time.

      * NOTE: If you need aditional functionality from MAST before
      your deployment this is possible, just wrap everything in
      your shell or batch script as normal using MAST''s Command
      Line Interface.

   * postdeploy_command:

      * This is a command which will be issued to your underlying OS
      after the deployment/migration is completed.
      This is provided for the purposes of cleaning up anything
      from your VCS and/or for initiating your automated testing
      frameworks.

      * It is advised to wrap these commands in shell or batch
      scripts and call them so that the same actions are performed
      each time.

      * NOTE: If you need aditional functionality from MAST before
      your deployment this is possible, just wrap everything in
      your shell or batch script as normal using MAST''s Command
      Line Interface.

   * Import:

      * The following params must be specified:

         * Domain - The domain to which the deployment should be done.
         This will also be used if you choose to save config afterwards.

         * file_in - This is the configuration file that you are
         importing. It must be in the format specified by the format
         parameter.

         * deployment_policy - This is optional. It is the deployment
         policy to be used when importing the configuration to the
         specified domain. This must already exist as an object in
         the specified domain.

         * dry_run - Whether to perform this as a dry-run to see
         exactly what changes will be performed when you actually
         do the deployment.

         * overwrite_files - Whether to overwrite existing files
         when importing the configuration.

         * overwrite_objects - Whether to overwrite existing objects
         when importing the configuration.

         * rewrite_local_ip - Whether to overwrite the local IP
         Addresses when importing the configuration.

         * format - The format of the configuration file, must be
         either "ZIP" or "XML".

   * Domain Quiesce
     * The following params must be specified:
        * quiesce_domain - Whether to quiesce the domain.

        * Domain - This is shared among other actions. The domain to
        quiesce.

        * quiesce_timeout - This is shared among other actions. The
        timeout before quiescing the domain. NOTE: This value must
        be a minumum of 60.

   * Appliance Quiesce
     * The following params must be specified:
        * quiesce_appliance - Whether to quiesce the appliances.

        * quiesce_timeout - This is shared among other actions. The
        timeout before quiescing the appliance


   * unquiesce_domain - Whether to unquiesce the specified domain

   * unquiesce_appliance - Whether to unquiesce the appliances

   * object_audit:

      * Whether to perform an object audit after the import, but
      before the save_config. An object audit is simply a diff
      between the running and persisted configuration. This will
      be available in the download after the deployment.

   * out_dir:

      * (NOT NEEDED IN THE WEB GUI) This is where you would like
      all of the output files to be placed.
"""

    if web:
        from mast.backups import set_checkpoint, get_normal_backup, get_secure_backup
        import mast.system as system
        from mast.developer import _import
    else:
        #lint:disable
        from mast.backups import set_checkpoint
        from mast.backups import get_normal_backup, get_secure_backup
        import mast.system as system
        from mast.developer import _import
        #lint:enable

    if web:
        output = ""
        history = ""

    if predeploy_command:
        logger.info(
            "Pre-Deployment command '{}' found. Executing at {}".format(
                predeploy_command, str(Timestamp())))

        os.system(predeploy_command)

        logger.info(
            "finished executing Pre-Deployment command '{}' at {}.".format(
                predeploy_command, str(Timestamp())))

    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    for appliance in env.appliances:
        appliance.log_info("Deployment started on {}".format(
            appliance.hostname))

        # Quiesce Domain
        if quiesce_domain:
            logger.info(
                "Quiescing domain {} before deployment at {}".format(
                    Domain, str(Timestamp())))

            resp, hist = system.quiesce_domain(
                appliance.hostname,
                credentials,
                timeout,
                Domain,
                quiesce_timeout,
                no_check_hostname=no_check_hostname,
                web=web)

            logger.info(
                "Finished quiescing domain {} before deployment at {}".format(
                    Domain, str(Timestamp())))

            sleep(quiesce_timeout)

            if web:
                output += resp
                history += hist

        # Quiesce Appliance
        if quiesce_appliance:
            logger.info(
                "Quiescing appliances before deployment at {}".format(
                    str(Timestamp())))

            resp, hist = system.quiesce_appliance(
                appliance.hostname,
                credentials,
                timeout,
                quiesce_timeout,
                no_check_hostname=no_check_hostname,
                web=web)

            logger.info(
                "Finished quiescing appliances before deployment at {}".format(
                    str(Timestamp())))

            sleep(quiesce_timeout)

            if web:
                output += resp
                history += hist

        appliance.log_info("Attempting to import configuration at '{}'".format(
            str(Timestamp())))

        file_out = os.path.join(
            out_dir, '{}-deployment_results.txt'.format(appliance.hostname))

        # import configuration
        resp, hist = _import(
            appliance.hostname, credentials, timeout, Domain, file_in,
            deployment_policy, dry_run, overwrite_files, overwrite_objects,
            rewrite_local_ip, format, file_out, no_check_hostname=no_check_hostname,
            web=web)

        if web:
            output += resp
            history += hist

        appliance.log_info("Finished importing configuration at {}".format(
            str(Timestamp())))

        # unquiesce domain
        if quiesce_domain:
            appliance.log_info("Attempting to unquiesce domain")

            resp, hist = system.unquiesce_domain(
                appliance.hostname,
                credentials,
                timeout,
                Domain,
                no_check_hostname=no_check_hostname,
                web=web)

            appliance.log_info("Finished unquiescing domain")

            if web:
                output += resp
                history += hist

        # unquiesce appliance
        if quiesce_appliance:
            logger.info(
                "Quiescing appliances before deployment at {}".format(
                    str(Timestamp())))

            resp, hist = system.unquiesce_appliance(
                appliance.hostname,
                credentials,
                timeout,
                no_check_hostname=no_check_hostname,
                web=web)

            logger.info(
                "Finished quiescing appliances before deployment at {}".format(
                    str(Timestamp())))

            if web:
                output += resp
                history += hist

        if object_audit:
            appliance.log_info(
                "Post-Deployment Object audit started at {}".format(
                str(Timestamp())))

            resp, hist = system.objects_audit(appliance.hostname, credentials,
                timeout, out_dir, no_check_hostname=no_check_hostname, web=web)

            appliance.log_info(
                "Post-Deployment Object audit finished at {}".format(
                str(Timestamp())))

            if web:
                output += resp
                history += hist

    if postdeploy_command:
        logger.info(
            "Post-Deployment command '{}' found. Executing at {}".format(
                postdeploy_command, str(Timestamp())))

        os.system(postdeploy_command)

        logger.info(
            "finished executing Post-Deployment command '{}' at {}.".format(
                postdeploy_command, str(Timestamp())))

    if web:
        return output, history


@logged('mast.datapower.deployment')
@cli.command('postdeploy', category='deployment')
def postdeploy(appliances=[], credentials=[], timeout=120,
    Domain="", save_config=True, no_check_hostname=False, web=True):
    """This is a simple script which will allow you to unquiesce
   your domain or appliances after you quiesce them for a deployment.
   Also this will allow you to save the config.

   * Domain - The domain which will be unquiesced

   * save_config - Whether to save the configuration in the specified
   domain."""
    if web:
        import mast.system as system
    else:
        #lint:disable
        import mast.system as system
        #lint:enable

    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    if web:
        output = ""
        history = ""
    for appliance in env.appliances:

        #if unquiesce_domain:
            #appliance.log_info("Attempting to unquiesce domain")

            #resp, hist = system.unquiesce_domain(
                #appliance.hostname,
                #credentials,
                #timeout,
                #Domain,
                #web=web)

            #appliance.log_info("Finished unquiescing domain")

            #if web:
                #output += resp
                #history += hist

        #if unquiesce_appliance:
            #logger.info(
                #"Quiescing appliances before deployment at {}".format(
                    #str(Timestamp())))

            #resp, hist = system.unquiesce_appliance(
                #appliance.hostname,
                #credentials,
                #timeout,
                #web=web)

            #logger.info(
                #"Finished quiescing appliances before deployment at {}".format(
                    #str(Timestamp())))

            #if web:
                #output += resp
                #history += hist

        if save_config:
            appliance.log_info(
                "Attempting to save configuration after deployment")

            resp, hist = system.save_config(
                appliance.hostname,
                credentials,
                timeout,
                Domain,
                no_check_hostname=no_check_hostname,
                web=web)

            appliance.log_info("Finished saving configuration after deployment")

            if web:
                output += resp
                history += hist
    if web:
        return output, history


@logged('mast.datapower.deployment')
def get_data_file(f):
    _root = os.path.dirname(__file__)
    path = os.path.join(_root, "data", f)
    with open(path, "rb") as fin:
        return fin.read()

from mast.plugins.web import Plugin
import mast.plugin_utils.plugin_functions as pf
from functools import partial, update_wrapper


class WebPlugin(Plugin):
    def __init__(self):
        self.route = partial(pf.handle, "deployment")
        self.route.__name__ = "deployment"
        self.html = partial(pf.html, "mast.datapower.deployment")
        update_wrapper(self.html, pf.html)

    def css(self):
        return get_data_file('plugin.css')

    def js(self):
        return get_data_file('plugin.js')


if __name__ == '__main__':
    try:
        cli.Run()
    except AttributeError, e:
        if "'NoneType' object has no attribute 'app'" in e:
            raise NotImplementedError(
                "HTML formatted output is not supported on the CLI")
    except ImportError, e:
        if "No module named backups" in e:
            raise NotImplementedError(
                "HTML formatted output is not supported on the CLI")
