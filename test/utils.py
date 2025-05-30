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
    UBERON_0001013: str = "Adipose Tissue"
    UBERON_0000178: str = "Blood"
    UBERON_0001474: str = "Bone"
    UBERON_0002371: str = "Bone Marrow"
    UBERON_0000955: str = "Brain"
    UBERON_0000948: str = "Heart"
    UBERON_0004538: str = "Kidney (Left)"
    UBERON_0004539: str = "Kidney (Right)"
    UBERON_0000059: str = "Large Intestine"
    UBERON_0002107: str = "Liver"
    UBERON_0002168: str = "Lung (Left)"
    UBERON_0002167: str = "Lung (Right)"
    UBERON_0000029: str = "Lymph Node"
    UBERON_0001911: str = "Mammary Gland"
    FMA_57991: str = "Mammary Gland (Left)"
    FMA_57987: str = "Mammary Gland (Right)"
    UBERON_0005090: str = "Muscle"
    UBERON_0010000: str = "Other"
    UBERON_0002119: str = "Ovary (Left)"
    UBERON_0002118: str = "Ovary (Right)"
    UBERON_0001264: str = "Pancreas"
    UBERON_0001987: str = "Placenta"
    UBERON_0002097: str = "Skin"
    UBERON_0002240: str = "Spinal Cord"
    UBERON_0002106: str = "Spleen"
    UBERON_0002370: str = "Thymus"
    FMA_54974: str = "Tonsil (Left)"
    FMA_54973: str = "Tonsil (Right)"
    UBERON_0003126: str = "Trachea"

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
            return {e.name.replace("_", ":"): e.default for e in fields(OrganTypes)}
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
