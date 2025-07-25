import logging
import os
import shutil
import threading

from hubmap_commons import file_helper
from hubmap_commons.exceptions import HTTPException
from hubmap_commons.hm_auth import AuthHelper


class IngestFileHelper:

    def __init__(self, config):
        self.appconfig = config
        self.logger = logging.getLogger("ingest.service")
        self.auth_helper = AuthHelper.configured_instance(
            config["APP_CLIENT_ID"], config["APP_CLIENT_SECRET"]
        )

    @staticmethod
    def make_directory(new_file_path, symbolic_file_path=None):
        os.makedirs(new_file_path)
        # make a sym link too
        if symbolic_file_path != None:
            os.symlink(new_file_path, symbolic_file_path, True)
        return new_file_path

    def dataset_asset_directory_absolute_path(self, dataset_uuid):
        return (
            file_helper.ensureTrailingSlashURL(self.appconfig["SENNET_WEBSERVICE_FILEPATH"])
            + dataset_uuid
        )

    def get_dataset_directory_absolute_path(self, dataset_record, group_uuid, dataset_uuid):
        if "contains_human_genetic_sequences" not in dataset_record:
            self.logger.info(
                f"get_dataset_directory_absolute_path: contains_human_genetic_sequences is None {dataset_uuid}"
            )

        if (
            "contains_human_genetic_sequences" in dataset_record
            and dataset_record["contains_human_genetic_sequences"]
        ):
            access_level = self.appconfig["ACCESS_LEVEL_PROTECTED"]
        elif not "data_access_level" in dataset_record:
            access_level = self.appconfig["ACCESS_LEVEL_CONSORTIUM"]
        else:
            access_level = dataset_record["data_access_level"]

        published = False
        if "status" in dataset_record and dataset_record["status"] == "Published":
            published = True

        return self.dataset_directory_absolute_path(
            access_level, group_uuid, dataset_uuid, published
        )

    def dataset_directory_absolute_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == "protected":
            base_dir = self.appconfig["GLOBUS_PROTECTED_ENDPOINT_FILEPATH"]
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        elif published:
            base_dir = self.appconfig["GLOBUS_PUBLIC_ENDPOINT_FILEPATH"]
            abs_path = str(os.path.join(base_dir, dataset_uuid))
        else:
            base_dir = self.appconfig["GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH"]
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))

        return abs_path

    def get_dataset_directory_relative_path(self, dataset_record, group_uuid, dataset_uuid):
        if "contains_human_genetic_sequences" not in dataset_record:
            self.logger.info(
                f"get_dataset_directory_relative_path: contains_human_genetic_sequences is None {dataset_uuid}"
            )

        if (
            "contains_human_genetic_sequences" in dataset_record
            and dataset_record["contains_human_genetic_sequences"]
        ):
            access_level = "protected"
        elif not "data_access_level" in dataset_record:
            access_level = "consortium"
        else:
            access_level = dataset_record["data_access_level"]

        published = False
        if "status" in dataset_record and dataset_record["status"] == "Published":
            published = True

        return self.__dataset_directory_relative_path(
            access_level, group_uuid, dataset_uuid, published
        )

    def get_upload_directory_relative_path(self, group_uuid, upload_uuid):
        return self.__dataset_directory_relative_path("protected", group_uuid, upload_uuid, False)

    def __dataset_directory_relative_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == "protected":
            endpoint_id = self.appconfig["GLOBUS_PROTECTED_ENDPOINT_UUID"]
            rel_path = str(
                os.path.join(
                    self.appconfig["RELATIVE_GLOBUS_PROTECTED_ENDPOINT_FILEPATH"],
                    grp_name,
                    dataset_uuid,
                )
            )
        elif published:
            endpoint_id = self.appconfig["GLOBUS_PUBLIC_ENDPOINT_UUID"]
            rel_path = str(
                os.path.join(
                    "/", dataset_uuid
                )
            )
        else:
            endpoint_id = self.appconfig["GLOBUS_CONSORTIUM_ENDPOINT_UUID"]
            rel_path = str(
                os.path.join(
                    self.appconfig["RELATIVE_GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH"],
                    grp_name,
                    dataset_uuid,
                )
            )

        return {"rel_path": rel_path, "globus_endpoint_uuid": endpoint_id}

    def create_dataset_directory(self, dataset_record, group_uuid, dataset_uuid):
        try:
            if dataset_record["contains_human_genetic_sequences"]:
                access_level = self.appconfig["ACCESS_LEVEL_PROTECTED"]
                asset_link_dir = None
            else:
                access_level = self.appconfig["ACCESS_LEVEL_CONSORTIUM"]
                # if the dataset is consortium level provide the path in the assets directory
                # to link it to, if protected don't link into assets directory (above set to None)
                asset_link_dir = os.path.join(
                    str(self.appconfig["SENNET_WEBSERVICE_FILEPATH"]), dataset_record["uuid"]
                )

            self.logger.info(
                f"Getting dataset directory absolute path ... {access_level}, {asset_link_dir} "
            )

            new_directory_path = self.get_dataset_directory_absolute_path(
                dataset_record, group_uuid, dataset_uuid
            )

            self.logger.info(f"To create dataset directory: {new_directory_path}")

            IngestFileHelper.make_directory(new_directory_path, asset_link_dir)

            self.logger.info(f"Checking access levels ... ")

            if dataset_record["contains_human_genetic_sequences"]:
                access_level = self.appconfig["ACCESS_LEVEL_PROTECTED"]
            else:
                access_level = self.appconfig["ACCESS_LEVEL_CONSORTIUM"]

            self.logger.info(f"Access level {access_level}")
            """
            Comment out pending SenNet revisions for AWS filesystem
            x = threading.Thread(target=self.set_dir_permissions, args=[access_level, new_directory_path])
            x.start()
            """
        except Exception as e:
            self.logger.error(e, exc_info=True)

    def set_dir_permissions(self, access_level, file_path, published=False, trial_run=False):
        try:

            mode = 0o750  # rwxr-x---
            if not published:
                if access_level in [
                    self.appconfig["ACCESS_LEVEL_PUBLIC"],
                    self.appconfig["ACCESS_LEVEL_CONSORTIUM"],
                ]:
                    mode = 0o755  # rwxr-xr-x
            else:
                mode = 0o550  # r-xr-x---
                if access_level == self.appconfig["ACCESS_LEVEL_PUBLIC"]:
                    mode = 0o555  # r-xr-xr-x

            # since mode value is octal literal, let's get its string representation removing the proceeding 0o
            octal_representation = oct(mode)[2:]
            # put quotes around the path since it often contains spaces
            chmod_command = f"chmod {octal_representation} '{file_path}'"
            self.logger.info(
                f"Executing chmod with mode: {octal_representation} and permissions {access_level}"
            )
            if not trial_run:
                # apply the permissions
                os.chmod(file_path, mode)
            else:
                print(chmod_command)
            return chmod_command
        except Exception as e:
            self.logger.error(e, exc_info=True)

    def move_dataset_files_for_publishing(
        self, uuid, group_uuid, dataset_access_level, trial_run=False, to_symlink_path=None
    ):
        from_path = self.dataset_directory_absolute_path(
            dataset_access_level, group_uuid, uuid, False
        )
        if not os.path.isdir(from_path) and to_symlink_path is None:
            raise HTTPException(
                f"{uuid}: path not found to dataset will not publish, path is {from_path}", 500
            )
        data_access_level = "protected"
        if not dataset_access_level == "protected":
            data_access_level = "public"
        to_path = self.dataset_directory_absolute_path(data_access_level, group_uuid, uuid, True)
        if not trial_run:
            if to_symlink_path is not None:
                os.symlink(to_symlink_path, to_path, True)
            else:
                shutil.move(from_path, to_path)
        else:
            print(f"mv {from_path} {to_path}")

        return None

    def get_upload_directory_absolute_path(self, group_uuid, upload_uuid):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        base_dir = self.appconfig["GLOBUS_PROTECTED_ENDPOINT_FILEPATH"]
        abs_path = str(os.path.join(base_dir, grp_name, upload_uuid))
        return abs_path

    def create_upload_directory(self, group_uuid, upload_uuid):
        new_directory_path = self.get_upload_directory_absolute_path(group_uuid, upload_uuid)
        IngestFileHelper.make_directory(new_directory_path, None)
        try:
            x = threading.Thread(
                target=self.set_dir_permissions, args=["protected", new_directory_path]
            )
            x.start()
        except Exception as e:
            self.logger.error(e, exc_info=True)

    def set_dataset_permissions(
        self, dataset_uuid, group_uuid, dataset_access_level, published, trial_run=False
    ):
        file_path = self.dataset_directory_absolute_path(
            dataset_access_level, group_uuid, dataset_uuid, published
        )
        return self.set_dir_permissions(
            dataset_access_level, file_path, published, trial_run=trial_run
        )

    def relink_to_public(self, dataset_uuid):
        lnk_path = self.appconfig["SENNET_WEBSERVICE_FILEPATH"]
        lnk_path = lnk_path.strip()
        if lnk_path[-1] == "/":
            lnk_path = lnk_path[:-1]
        lnk_path = self.dataset_asset_directory_absolute_path(dataset_uuid)
        pub_path = (
            file_helper.ensureTrailingSlashURL(self.appconfig["GLOBUS_PUBLIC_ENDPOINT_FILEPATH"])
            + dataset_uuid
        )
        try:
            os.unlink(lnk_path)
        except:
            print("Error unlinking " + lnk_path)

        if os.path.exists(pub_path):
            file_helper.linkDir(pub_path, lnk_path)
