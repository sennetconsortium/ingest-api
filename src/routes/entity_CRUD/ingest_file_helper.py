import os
import logging
from hubmap_commons.hm_auth import AuthHelper

class IngestFileHelper:

    def __init__(self, config):
        self.appconfig = config
        self.logger = logging.getLogger('ingest.service')
        self.auth_helper = AuthHelper.configured_instance(config['APP_CLIENT_ID'], config['APP_CLIENT_SECRET'] )

    @staticmethod
    def make_directory(new_file_path, symbolic_file_path=None):
        os.makedirs(new_file_path)
        # make a sym link too
        if symbolic_file_path != None:
            os.symlink(new_file_path, symbolic_file_path, True)
        return new_file_path

    def get_dataset_directory_absolute_path(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = self.appconfig['ACCESS_LEVEL_PROTECTED']
        elif not 'data_access_level' in dataset_record:
            access_level = self.appconfig['ACCESS_LEVEL_CONSORTIUM']
        else:
            access_level = dataset_record['data_access_level']

        published = False
        if 'status' in dataset_record and dataset_record['status'] == 'Published':
            published = True

        return self.__dataset_directory_absolute_path(access_level, group_uuid, dataset_uuid, published)

    def __dataset_directory_absolute_path(self, access_level, group_uuid, dataset_uuid, published):
        grp_name = AuthHelper.getGroupDisplayName(group_uuid)
        if access_level == 'protected':
            base_dir = self.appconfig['GLOBUS_PROTECTED_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))
        elif published:
            base_dir = self.appconfig['GLOBUS_PUBLIC_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, dataset_uuid))
        else:
            base_dir = self.appconfig['GLOBUS_CONSORTIUM_ENDPOINT_FILEPATH']
            abs_path = str(os.path.join(base_dir, grp_name, dataset_uuid))

        return abs_path

    def create_dataset_directory(self, dataset_record, group_uuid, dataset_uuid):
        if dataset_record['contains_human_genetic_sequences']:
            access_level = self.appconfig['ACCESS_LEVEL_PROTECTED']
            asset_link_dir = None
        else:
            access_level = self.appconfig['ACCESS_LEVEL_CONSORTIUM']
            #if the dataset is consortium level provide the path in the assets directory
            #to link it to, if protected don't link into assets directory (above set to None)
            asset_link_dir = os.path.join(str(self.appconfig['SENNET_WEBSERVICE_FILEPATH']), dataset_record['uuid'])

        new_directory_path = self.get_dataset_directory_absolute_path(dataset_record, group_uuid, dataset_uuid)
        
        self.logger.info(f'To create dataset directory: {new_directory_path}')
        
        IngestFileHelper.make_directory(new_directory_path, asset_link_dir)
        
        try:
            if dataset_record['contains_human_genetic_sequences']:
                access_level = self.appconfig['ACCESS_LEVEL_PROTECTED']
            else:
                access_level = self.appconfig['ACCESS_LEVEL_CONSORTIUM']
            '''
            Comment out pending SenNet revisions for AWS filesystem
            x = threading.Thread(target=self.set_dir_permissions, args=[access_level, new_directory_path])
            x.start()
            '''
        except Exception as e:
            self.logger.error(e, exc_info=True)

    '''
    Comment out pending SenNet revisions for AWS filesystem
    def set_dir_permissions(self, access_level, file_path, published = False, trial_run = False):
        acl_text = None
        if not published:
            if access_level == HubmapConst.ACCESS_LEVEL_PROTECTED:
                acl_text = 'u::rwx,g::r-x,o::---,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,g:{seq_group}:r-x,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group:{seq_group}:r-x,d:group::r-x,d:mask::rwx,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
                acl_text = 'u::rwx,g::r-x,o::---,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,g:{consortium_group}:r-x,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group:{consortium_group}:r-x,d:group::r-x,d:mask::rwx,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
                acl_text = 'u::rwx,g::r-x,o::r-x,m::rwx,u:{hive_user}:rwx,u:{admin_user}:rwx,d:user::rwx,d:user:{hive_user}:rwx,d:user:{admin_user}:rwx,d:group::r-x,d:mask::rwx,d:other:r-x'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
        else:
            if access_level == HubmapConst.ACCESS_LEVEL_PROTECTED:
                acl_text = 'u::r-x,g::r-x,o::---,m::rwx,u:{hive_user}:r-x,u:{admin_user}:r-x,g:{seq_group}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group:{seq_group}:r-x,d:group::r-x,d:mask::r-x,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_CONSORTIUM:
                acl_text = 'u::r-x,g::r-x,o::---,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,g:{consortium_group}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:r-x,d:group:{consortium_group}:r-x,d:group::r-x,d:mask::r-x,d:other:---'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])
            if access_level == HubmapConst.ACCESS_LEVEL_PUBLIC:
                acl_text = 'u::r-x,g::r-x,o::r-x,m::r-x,u:{hive_user}:r-x,u:{admin_user}:r-x,d:user::r-x,d:user:{hive_user}:r-x,d:user:{admin_user}:rwx,d:group::r-x,d:mask::r-x,d:other:r-x'.format(
                    hive_user=self.appconfig['GLOBUS_BASE_FILE_USER_NAME'],admin_user=self.appconfig['GLOBUS_ADMIN_FILE_USER_NAME'],
                    seq_group=self.appconfig['GLOBUS_GENOMIC_DATA_FILE_GROUP_NAME'],
                    consortium_group=self.appconfig['GLOBUS_CONSORTIUM_FILE_GROUP_NAME'])

        # apply the permissions
        # put quotes around the path since it often contains spaces
        facl_command = "setfacl" + ' -R -b' +  ' --set=' + acl_text + " '" + file_path + "'"
        self.logger.info("Executing command: " + facl_command)
        if not trial_run:
            subprocess.Popen(['setfacl','-R', '-b', '--set=' + acl_text, file_path ])
        else:
            print(facl_command)
        return facl_command
    '''
