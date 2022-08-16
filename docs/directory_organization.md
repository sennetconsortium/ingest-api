## SenNet Data Directory Organization

SenNet data is organized by access level (protected, consortium or public), data provider and uuid.  Both Datasets and data Uploads are stored in the structure described here.

### Directory scheme

 `<base directory>/<access level>/<data provider name>/<uuid>/`

 - **base directory**: The base directory in the CODCC file system as defined by the `LOCAL_STORAGE_DIRECTORY` in `src/instance/app.cfg`
 - **access level: The access level of the data, one of the followning values
   - **protected**: The data is protected, only users who are members of the data provider access group (see [Globus Groups](/docs/globus_data_access_groups.md)) or the SenNet Protected Data access group can access the data via Globus.  On CODCC systems members of the group `@todo` can access the data.  Data is protected for all Uploads.  Datasets are protected if the data contained within contains any human genomic sequence information.
   - **consortium**: The data is accessible to all SenNet Consortium members.  You must be a member of the Globus SenNet-Read group for read access to the data via Globus or a member of the `@todo` group on CODCC systems.
   - **public**: The data is publicly readable.  Any user who authenticates in Globus can access the data.  Any user on the CODCC systems can read the data.
 - **data provider name**: For **protected** and **consortium** data only, this additional directory is not used for **public** data.  The name of the data provider as defined by the `displayname` field for the data provider in the [group information file](https://github.com/sennetconsortium/commons/blob/master/hubmap_commons/hubmap-globus-groups.json) in the `HuBMAP Commons` repository.
 - **uuid**: The `uuid` of the SenNet Entity (Dataset or Upload).
