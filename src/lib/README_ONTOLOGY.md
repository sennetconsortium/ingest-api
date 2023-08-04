# Ontology
The Ontology helper class will allow for requesting various nodes within the UBKG ecosystem. 
app.cfg must be set up. See [the docs for details.](https://github.com/x-atlas-consortia/commons/tree/main/atlas_consortia_commons/ubkg)

## Transforming UBKG results using the Ontology class.
Node result set can be transformed with various options. 
### Options
```
as_arr = False  # Return as an array/list
cb = str  # The callback function to run on value of the transform result 
as_data_dict = False  # Return as a dict
prop_callback = to_snake_case_upper  # The callback to apply on the dict key of the transform result 
data_as_val = False  # Whether to return the full UBKG data as value of key
url_params = None  # Url parameters to apply to the request
key = 'term'  # Which property value from the item to return as the key of the transform result 
val_key = None  # Which property value from the item to return as the value of the transform result 
```

### Examples:
```
Ontology.ops().entities()
```
Will yield a class with name `Entities`:
```
<class 'atlas_consortia_commons.object.Entities'>
Entities.DATASET
```

`Ontology.ops(as_arr=True, cb=enum_val_lower).entities()`
Will return a list of strings from the `term` key property
```
['dataset', 'sample', 'source', 'publication entity']
```

`Ontology.ops(as_arr=True, key='code', cb=enum_val_lower).entities()`
Will return a list of strings from the `code` key property
```
['c050002', 'c050003', 'c050004', 'c050021']
```

`Ontology.ops(as_data_dict=True, data_as_val=True).entities()`
Will return the following transform result:
```
{'DATASET': {'code': 'C050002', 'sab': 'SENNET', 'term': 'Dataset'}, 'SAMPLE': {'code': 'C050003', 'sab': 'SENNET', 'term': 'Sample'}, 'SOURCE': {'code': 'C050004', 'sab': 'SENNET', 'term': 'Source'}, 'PUBLICATION_ENTITY': {'code': 'C050021', 'sab': 'SENNET', 'term': 'Publication Entity'}}
```

If call say `Ontology.ops().specimen_categories()` directly after a previous call with `ops(...)` settings, the settings will be reused from the last call.
To make a fresh call on each request with default options, use `Ontology.ops().*`.


## Retrieving raw UBKG results
May also retrieve the raw UBKG results
### By Valueset
To retrieve a node whose app.cfg is setup to use `UBKG_ENDPOINT_VALUESET`
```
current_app.ubkg.get_ubkg_valueset(current_app.ubkg.specimen_categories)
```

### By Endpoint
If a particular node name has a specific endpoint set in `app.cfg.UBKG_CODES`
```
current_app.ubkg.get_ubkg_by_endpoint(current_app.ubkg.organ_types)
```

### Additional
May pass another endpoint.
```
current_app.ubkg.get_ubkg(current_app.ubkg.assay_types, prefix_key, f"{endpoint}{url_params}")
```