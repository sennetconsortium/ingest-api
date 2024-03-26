# Validating metadata 

## Validate using form data
`POST /metadata/validate`

### Payload (Form Data):
```
metadata: (binary) # this is the TSV upload
entity_type: Source
sub_type: murine
```

### Sample response:
The response will contain the `metadata` to be stored in db, and the `pathname` which can be used for reference and revalidation purposes
```
{ code: 200
metadata: [{bedding: "Aspen chip", cage_enhancements: "Nestlets",…}]
pathname: "cr46sq7pbn594v2btqst/example_source_mouse_metadata.tsv"}
```

## Validate using json
Can actually pass a pathname to file. This is useful for revalidating a tsv file and comparing its metadata response to another.
Actually done in entity-api to verify that the posted `metadata` from the portal-ui is valid.
### Payload (JSON):
```
{pathname: "cr46sq7pbn594v2btqst/example_source_mouse_metadata.tsv",
entity_type: Source,
sub_type: murine}
```

## Verify a certain TSV row
If want to validate a certain row on file, pass `tsv_row`
### Payload (JSON):
```
{pathname: "cr46sq7pbn594v2btqst/example_source_mouse_metadata.tsv",
tsv_row: 3,
entity_type: Source,
sub_type: murine,}
```

## Failed Response
Failed responses will return status of `406 Not Acceptable`.
```
{code:406,
description: [0:"Unexpected fields: {'area_value', 'section_thickness_unit', 'section_thickness_value', 'area_unit', 'histological_report', 'section_index_number'}"
1:"Missing fields: {'suspension_enriched_target', 'suspension_entity_number', 'suspension_entity', 'suspension_enriched'}"
2:"In column 13, found \"histological_report\", expected \"suspension_entity\"",…],
name:"Unacceptable Metadata"}
```