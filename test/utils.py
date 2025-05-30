import json
from dataclasses import dataclass, fields

from atlas_consortia_commons.object import enum_val_lower
from requests import Response

from lib.ontology import Ontology


@dataclass
class SpecimenCategories:
    BLOCK: str = "Block"
    ORGAN: str = "Organ"
    SECTION: str = "Section"
    SUSPENSION: str = "Suspension"


@dataclass
class Entities:
    DATASET: str = "Dataset"
    PUBLICATION_ENTITY: str = "Publication Entity"
    SAMPLE: str = "Sample"
    SOURCE: str = "Source"


@dataclass
class SourceTypes:
    MOUSE: str = "Mouse"
    HUMAN: str = "Human"
    HUMAN_ORGANOID: str = "Human Organoid"
    MOUSE_ORGANOID: str = "Mouse Organoid"


@dataclass
class DatasetTypes:
    HISTOLOGY: str = "Histology"
    MOLECULAR_CARTOGRAPHY: str = "Molecular Cartography"
    RNASEQ: str = "RNASeq"
    ATACSEQ: str = "ATACSeq"
    SNARESEQ2: str = "SNARE-seq2"
    PHENOCYCLER: str = "PhenoCycler"
    CYCIF: str = "CyCIF"
    MERFISH: str = "MERFISH"
    MALDI: str = "MALDI"
    _2D_IMAGING_MASS_CYTOMETRY: str = "2D Imaging Mass Cytometry"
    NANOSPLITS: str = "nanoSPLITS"
    AUTOFLUORESCENCE: str = "Auto-fluorescence"
    CONFOCAL: str = "Confocal"
    THICK_SECTION_MULTIPHOTON_MXIF: str = "Thick section Multiphoton MxIF"
    SECOND_HARMONIC_GENERATION_SHG: str = "Second Harmonic Generation (SHG)"
    ENHANCED_STIMULATED_RAMAN_SPECTROSCOPY_SRS: str = "Enhanced Stimulated Raman Spectroscopy (SRS)"
    SIMS: str = "SIMS"
    CELL_DIVE: str = "Cell DIVE"
    CODEX: str = "CODEX"
    LIGHTSHEET: str = "Lightsheet"
    MIBI: str = "MIBI"
    LCMS: str = "LC-MS"
    DESI: str = "DESI"
    _10X_MULTIOME: str = "10x Multiome"
    VISIUM: str = "Visium"


@dataclass
class OrganTypes:
    AD: str = "Adipose Tissue"
    BD: str = "Blood"
    BR: str = "Brain"
    BS: str = "Breast"
    LK: str = "Kidney (Left)"
    RK: str = "Kidney (Right)"
    LI: str = "Large Intestine"
    LV: str = "Liver"
    LL: str = "Lung (Left)"
    RL: str = "Lung (Right)"
    LN: str = "Lymph Node"
    MU: str = "Muscle"
    LO: str = "Ovary (Left)"
    RO: str = "Ovary (Right)"
    SK: str = "Skin"


class MockOntology(Ontology):
    @staticmethod
    def entities():
        if Ontology.Ops.as_arr and MockOntology.Ops.cb == enum_val_lower:
            return [e.default.lower() for e in fields(Entities)]
        if MockOntology.Ops.as_arr and MockOntology.Ops.cb == str:
            return [e.default for e in fields(Entities)]
        if MockOntology.Ops.as_data_dict:
            return {e.name: e.default for e in fields(Entities)}
        return Entities

    @staticmethod
    def specimen_categories():
        if MockOntology.Ops.as_arr and MockOntology.Ops.cb == enum_val_lower:
            return [e.default.lower() for e in fields(SpecimenCategories)]
        if MockOntology.Ops.as_arr and MockOntology.Ops.cb == str:
            return [e.default for e in fields(SpecimenCategories)]
        if MockOntology.Ops.as_data_dict:
            return {e.name: e.default for e in fields(SpecimenCategories)}
        return SpecimenCategories

    @staticmethod
    def source_types():
        if MockOntology.Ops.as_arr and MockOntology.Ops.cb == enum_val_lower:
            return [e.default.lower() for e in fields(SourceTypes)]
        if MockOntology.Ops.as_arr and MockOntology.Ops.cb == str:
            return [e.default for e in fields(SourceTypes)]
        if Ontology.Ops.as_data_dict:
            return {e.name: e.default for e in fields(SourceTypes)}
        return SourceTypes

    @staticmethod
    def organ_types():
        if Ontology.Ops.as_data_dict:
            return {e.name: e.default for e in fields(OrganTypes)}
        return OrganTypes

    @staticmethod
    def dataset_types():
        if Ontology.Ops.as_arr and MockOntology.Ops.cb == enum_val_lower:
            return [e.default.lower() for e in fields(DatasetTypes)]
        if MockOntology.Ops.as_arr and MockOntology.Ops.cb == str:
            return [e.default for e in fields(DatasetTypes)]
        if MockOntology.Ops.as_data_dict:
            return {e.name.removeprefix("_"): e.default for e in fields(DatasetTypes)}
        return DatasetTypes


def create_response(status_code, content=None):
    res = Response()
    res.status_code = status_code
    if content:
        res._content = json.dumps(content).encode("utf-8")
    return res
