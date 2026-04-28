import importlib.util
import unittest
from pathlib import Path

mod_path = Path(__file__).resolve().parents[1] / 'index_disa_downloads.py'
spec = importlib.util.spec_from_file_location('index_disa_downloads', mod_path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class IndexDisaDownloadsTests(unittest.TestCase):
    def test_classify_scap_and_manual(self):
        self.assertEqual(m.classify('Windows STIG SCAP Benchmark', 'https://example/a.zip'), 'scap_benchmark_zip')
        self.assertEqual(m.classify('Windows STIG', 'https://example/a.zip'), 'manual_stig_zip')

    def test_parse_html_zip_links(self):
        html = '<a title="Example STIG V1R2" href="/stigs/zip/U_Example_V1R2_STIG.zip">Download</a>'
        rows = m.parse_html(html, 'https://dl.dod.cyber.mil')
        self.assertEqual(rows[0]['title'], 'Example STIG V1R2')
        self.assertEqual(rows[0]['url'], 'https://dl.dod.cyber.mil/stigs/zip/U_Example_V1R2_STIG.zip')

    def test_parse_html_data_link_buttons(self):
        html = '''
        <button aria-label="Download Apache Server 2.4 Windows STIG"
                data-link="https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apache_Server_2-4_Windows_Y26M04_STIG.zip">
          Download
        </button>
        '''
        rows = m.parse_html(html, 'https://www.cyber.mil/stigs/downloads/')
        self.assertEqual(rows, [{
            'title': 'Apache Server 2.4 Windows STIG',
            'url': 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apache_Server_2-4_Windows_Y26M04_STIG.zip',
        }])

    def test_normalize_deduplicates_and_release(self):
        rows = m.normalize([
            {'title': 'Example STIG V1R2', 'url': 'https://x/U_Example_V1R2_STIG.zip'},
            {'title': 'Example STIG V1R2', 'url': 'https://x/U_Example_V1R2_STIG.zip'},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['release'], 'V1R2')

    def test_seed_downloads_include_next_flagship_families(self):
        rows = m.normalize(m.SEED_DOWNLOADS)
        urls = {row['url'] for row in rows}
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R4_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R4_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V3R4_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_7_V3R15_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R1_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_Linux_8_V2R5_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R6_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Oracle_Linux_9_V1R3_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Edge_V2R5_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Cisco_NX-OS_Switch_Y26M04_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apache_Server_2-4_Windows_Y26M04_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apache_Tomcat_Application_Server_9_V3R4_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apple_macOS_15_V1R7_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R1_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_SQL_Server_2022_Y26M04_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_IIS_10-0_Y26M04_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Office_365_ProPlus_V3R5_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Office_365_ProPlus_V3R8_STIG_SCAP_1-3_Benchmark.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_V6R7_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_Windows_V6R7_STIG_SCAP_1-3_Benchmark.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_Linux_V6R6_STIG_SCAP_1-3_Benchmark.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Pro_DC_Continuous_V2R1_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Pro_DC_Continuous_V2R1_STIG_SCAP_1-3_Benchmark.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Reader_DC_Continuous_V2R4_STIG_SCAP_1-3_Benchmark.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SLES_15_V2R7_STIG.zip', urls)
        self.assertIn('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_SLES_15_V2R8_STIG_SCAP_1-3_Benchmark.zip', urls)
        self.assertEqual(len(rows), 46)

if __name__ == '__main__':
    unittest.main()
