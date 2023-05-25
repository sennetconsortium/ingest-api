import json

from requests import Response


class SpecimenCategories:
    BLOCK = 'Block'
    ORGAN = 'Organ'
    SECTION = 'Section'
    SUSPENSION = 'Suspension'

class Entities:
    DATASET = 'Dataset'
    SAMPLE = 'Sample'
    SOURCE = 'Source'

def create_response(status_code, content=None):
    res = Response()
    res.status_code = status_code
    if content:
        res._content = json.dumps(content).encode('utf-8')
    return res

organ_types = {
    'AD': 'Adipose Tissue',
    'BD': 'Blood',
    'BR': 'Brain',
    'BS': 'Breast',
    'LK': 'Kidney (Left)',
    'RK': 'Kidney (Right)',
    'LI': 'Large Intestine',
    'LV': 'Liver',
    'LL': 'Lung (Left)',
    'RL': 'Lung (Right)',
    'LN': 'Lymph Node',
    'MU': 'Muscle',
    'LO': 'Ovary (Left)',
    'RO': 'Ovary (Right)',
    'SK': 'Skin'
}

assay_types = {
    'bulk-RNA': 'bulk-RNA',
    'CITE-Seq': 'CITE-Seq',
    'CODEX': 'CODEX',
    'codex_cytokit': 'codex_cytokit',
    'codex_cytokit_v1': 'codex_cytokit_v1',
    'CosMX (RNA)': 'CosMX (RNA)',
    'DBiT-seq': 'DBiT-seq',
    'FACS - Fluorescence-activated Cell Sorting': 'FACS - Fluorescence-activated Cell Sorting',
    'GeoMX (RNA)': 'GeoMX (RNA)',
    'image_pyramid': 'image_pyramid',
    'LC-MS': 'LC-MS',
    'Lightsheet': 'Lightsheet',
    'Mint-ChIP': 'Mint-ChIP',
    'publication_ancillary': 'publication_ancillary',
    'salmon_rnaseq_10x': 'salmon_rnaseq_10x',
    'salmon_rnaseq_bulk': 'salmon_rnaseq_bulk',
    'SASP': 'SASP',
    'scRNA-seq': 'scRNA-seq',
    'sn_atac_seq': 'sn_atac_seq',
    'snATAC-seq': 'snATAC-seq',
    'snRNA-seq': 'snRNA-seq',
    'Stained Slides': 'Stained Slides',
    'Visium': 'Visium'
}

source_types = ['mouse', 'human', 'human organoid', 'mouse organoid']

specimen_categories = ['organ', 'suspension', 'section', 'block']
