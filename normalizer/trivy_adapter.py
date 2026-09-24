# import  normalizer.ocsf_models
# # import json
# from typing import Any


# # with open("/app/bakery_shop.json", "r") as file:
# #      trivy_data = json.load(file)
# #      scanner_name = "Trivy"
# #      scanner_version = trivy_data["Trivy"].get("Version", "")

# #      # print(scanner_version)

# #      result = trivy_data["Results"]
     
# #      # print(len((trivy_data)["Results"][0]["Vulnerabilities"]))
# #      # print(len((trivy_data)["Results"][1]["Vulnerabilities"]))

# # def vuln_get_func():
# #      vulnerability_array=[]
# #      for j in range(len(result)):
# #           vulnerabilities = result[j]["Vulnerabilities"]
# #           for i in range(len(vulnerabilities)):
# #                vulnerability = vulnerabilities[i]
# #                vulnerability_array.append(vulnerability)
# #      return vulnerability_array

# # vulnerability_array = vuln_get_func()

# # print(len(vulnerability_array))




# class TrivyAdapter():

#     def __init__(self,scanner_name , scanner_version) -> None:
#          self.scanner_name: Any = scanner_name
#          self.scanner_version: Any = scanner_version


# #     def normalizer(self,source:dict):

# #          pass
#     def map_cvss(self,source:dict) -> list[normalizer.ocsf_models.CVSSObject]:
#          cvss_data = source.get("CVSS", [])
#          cvss_data_list=[]
#          if isinstance(cvss_data, dict):
#                for key,value in cvss_data.items():
                                        
#                                         cvss_object = normalizer.ocsf_models.CVSSObject(
#                                              source=key,
#                                              v2_score=value.get("V2Score", None),
#                                              v2_vector=value.get("V2Vector",None),
#                                              v3_score=value.get("V3Score", None),
#                                              v3_vector=value.get("V3Vector",None),
#                                              v4_vector=value.get("V40Vector",None),
#                                              v4_score=value.get("V40Score", None)
#                               )
#                                         cvss_data_list.append(cvss_object)

#          return cvss_data_list
               
         

#     def map_vulnerability(self, source:dict) -> list[normalizer.ocsf_models.VulnerabilityObject]:   
#          uid = source.get("PkgIdentifier").get("UID", "")
#          cve_id = source.get("VulnerabilityID", "")
#          title = source.get("Title","")
#          desc = source.get("Description","")
#          cwe_ids = source.get("CweIDs",[])
#          epss_score = source.get("epss_score",None)
#          references = source.get("References",[])
#          vendor_severity=source.get("VendorSeverity",{})
#          cvss_data_list = self.map_cvss(source)
#          severity_source=source.get("SeveritySource","")
#          vulnerability_object = normalizer.ocsf_models.VulnerabilityObject(
#                uid=uid,
#                cve_id=cve_id,
#                title=title,
#                desc=desc,
#                cvss = cvss_data_list,
#                cwe_ids=cwe_ids,
#                epss_score=epss_score,
#                references=references,
#                vendor_severity=vendor_severity,
#                severity_source=severity_source
#           )

#          return vulnerability_object

         

         
    

#     def map_resources(self,source:dict):
#                name = source.get("PkgID", "")
#                resource_type = "package"
#                installed_version=source.get("InstalledVersion","")
#                fixed_version = source.get("FixedVersion", "")


         
#                ResourceObject = normalizer.ocsf_models.ResourceObject(
#                name = name,
#                resource_type = resource_type,
#                installed_version = installed_version,
#                fixed_version= fixed_version,
#                )
#                return ResourceObject

#     def map_product(self):
#                name=self.scanner_name
#                version=self.scanner_version
#                vendor="Aqua Security"

#                ProductObject =   normalizer.ocsf_models.ProductObject(
#                                         name=name,
#                                         vendor=vendor,
#                                         version=version
#                                                   )
#                return ProductObject


#     def normalizer(self, source:dict):

#           finding_uid =source.get("PkgIdentifier",{}).get("UID", "")
#           severity = source.get("Severity","")
#           status=source.get("Status", "")
#           vulnerabilities = [self.map_vulnerability(source)]
#           resources=[self.map_resources(source)]
#           product=[self.map_product()]
#           source_metadata = {
#     "primary_url": source.get("PrimaryURL"),
#     "data_source": source.get("DataSource"),
#     "package_path": source.get("PkgPath"),
#     "layer": source.get("Layer"),
#     "published_date": source.get("PublishedDate"),
#     "last_modified_date": source.get("LastModifiedDate"),
# }
          

#           OCSFVulnerabilityFinding = normalizer.ocsf_models.OCSFVulnerabilityFinding(
#                finding_uid = finding_uid,
#                severity=severity,
#                status=status,
#                vulnerabilities = vulnerabilities,
#                resources = resources,
#                product = product,
#                source_metadata= source_metadata
#              )
          
#           return OCSFVulnerabilityFinding

# Trivy = TrivyAdapter(scanner_name, scanner_version)   

# # # mapped = Trivy.map_vulnerability(source = vulnerability_array[2])
# # # print(mapped)

# # # mapped_1 = Trivy.map_resources(source = vulnerability_array[4])
# # # print(mapped_1)

# # # mapped_2 = Trivy.map_product()
# # # print(mapped_2)

# # mapped_4 = Trivy.normalizer(source = vulnerability_array[2])
# # print(mapped_4)


# # normalized_vulnerability_array=[]
# # for i in range(len(vulnerability_array)):
# #      source_vuln = vulnerability_array[i]
# #      print(type(source_vuln))
# #      mapped_4 = Trivy.normalizer(source = source_vuln)
# #      normalized_vulnerability_array.append(mapped_4)

# # print(normalized_vulnerability_array)
# # print(len(normalized_vulnerability_array))

from typing import Any
import normalizer.ocsf_models


class TrivyAdapter:

    def __init__(
        self,
        scanner_name: str,
        scanner_version: str | None = None
    ) -> None:
        self.scanner_name: Any = scanner_name
        self.scanner_version: Any = scanner_version


    def map_cvss(
        self,
        source: dict
    ) -> list[normalizer.ocsf_models.CVSSObject]:

        cvss_data = source.get("CVSS", {})
        cvss_data_list = []

        if isinstance(cvss_data, dict):

            for key, value in cvss_data.items():

                if not isinstance(value, dict):
                    continue

                cvss_object = normalizer.ocsf_models.CVSSObject(
                    source=key,

                    v2_score=value.get("V2Score"),
                    v2_vector=value.get("V2Vector"),

                    v3_score=value.get("V3Score"),
                    v3_vector=value.get("V3Vector"),

                    v4_score=value.get("V40Score"),
                    v4_vector=value.get("V40Vector")
                )

                cvss_data_list.append(cvss_object)

        return cvss_data_list


    def map_vulnerability(
        self,
        source: dict
    ) -> normalizer.ocsf_models.VulnerabilityObject:

        pkg_identifier = source.get("PkgIdentifier") or {}

        uid = pkg_identifier.get("UID", "")

        cve_id = source.get("VulnerabilityID")
        title = source.get("Title")
        desc = source.get("Description")

        cwe_ids = source.get("CweIDs") or []

        epss_score = source.get("epss_score")

        references = source.get("References") or []

        vendor_severity = source.get("VendorSeverity") or {}

        severity_source = source.get("SeveritySource")

        cvss_data_list = self.map_cvss(source)

        vulnerability_object = (
            normalizer.ocsf_models.VulnerabilityObject(
                uid=uid,
                cve_id=cve_id,
                title=title,
                desc=desc,
                cvss=cvss_data_list,
                cwe_ids=cwe_ids,
                epss_score=epss_score,
                references=references,
                vendor_severity=vendor_severity,
                severity_source=severity_source
            )
        )

        return vulnerability_object


    def map_resources(
        self,
        source: dict
    ) -> normalizer.ocsf_models.ResourceObject:

        name = source.get("PkgID", "")

        installed_version = source.get("InstalledVersion")

        fixed_version = source.get("FixedVersion")

        resource_object = normalizer.ocsf_models.ResourceObject(
            name=name,
            resource_type="package",
            installed_version=installed_version,
            fixed_version=fixed_version
        )

        return resource_object


    def map_product(
        self
    ) -> normalizer.ocsf_models.ProductObject:

        product_object = normalizer.ocsf_models.ProductObject(
            name=self.scanner_name,
            vendor="Aqua Security",
            version=self.scanner_version
        )

        return product_object


    def normalizer(
        self,
        source: dict
    ) -> normalizer.ocsf_models.OCSFVulnerabilityFinding:

        pkg_identifier = source.get("PkgIdentifier") or {}

        finding_uid = pkg_identifier.get("UID", "")

        severity = source.get("Severity", "")

        status = source.get("Status", "")

        vulnerability = self.map_vulnerability(source)

        resource = self.map_resources(source)

        product = self.map_product()

        source_metadata = {
            "primary_url": source.get("PrimaryURL"),
            "data_source": source.get("DataSource"),
            "package_path": source.get("PkgPath"),
            "layer": source.get("Layer"),
            "published_date": source.get("PublishedDate"),
            "last_modified_date": source.get("LastModifiedDate")
        }

        return normalizer.ocsf_models.OCSFVulnerabilityFinding(
            finding_uid=finding_uid,
            severity=severity,
            status=status,
            vulnerabilities=[vulnerability],
            resources=[resource],
            product=[product],
            source_metadata=source_metadata
        )