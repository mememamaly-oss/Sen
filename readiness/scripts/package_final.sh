#!/usr/bin/env bash
# Final packaging: complete bundle + full archive + evidence sync
set -e
R=/home/z/my-project/readiness
Z=$R/ziprun5                       # the FINAL verified tree
DL=/home/z/my-project/download
SR=$DL/sentinel-results

echo "== 1) refresh sentinel-results with the final gate artifacts =="
mkdir -p $SR
cp $R/evidence/A01_FULL_FINAL_v3.json $SR/tests_v400_FULL.json      # 83/83 from FINAL zip
cp $R/evidence/FINAL4_doctor.json $SR/doctor_v400.json              # 15/15 final
for i in 1 2 3; do cp $R/evidence/F3_bench_$i.json $SR/benchmark_v400_det$i.json; done
cp $R/evidence/live/C01_webgoat_v400.json $SR/scan_webgoat_v400_LIVE.json
cp $R/evidence/live/C02_webwolf_v400.json $SR/scan_webwolf_v400_LIVE.json
cp $R/evidence/live/C03_ginjuice_v400.json $SR/scan_ginjuice_v400_LIVE.json
cp $R/evidence/live/C04b_juiceshop_deep.json $SR/scan_juiceshop_v400_LIVE.json
cp $R/evidence/live/live_final.db $SR/sentinel_v400_live.db
cp $R/evidence/live/C13_webgoat_authz.json $SR/scan_webgoat_authz_v400_LIVE.json
cp $Z/docs/*.md $SR/docs/ 2>/dev/null || (mkdir -p $SR/docs && cp $Z/docs/*.md $SR/docs/)
cp $Z/CHANGELOG.md $SR/CHANGELOG.md
ls $SR | head -20

echo "== 2) build the complete bundle (source + gates) =="
BNDL=/tmp/sentinel-4.0.0-complete-bundle
rm -rf $BNDL && mkdir -p $BNDL
cd $BNDL
unzip -q $DL/sentinel-4.0.0-source.zip
mkdir -p results
cp $SR/tests_v400_FULL.json $SR/doctor_v400.json $SR/benchmark_v400_det*.json \
   $SR/scan_*_v400*.json $SR/executive_ginjuice_v400.json $SR/glass_ginjuice_v400.html \
   $SR/report_ginjuice_v400.html $SR/report_ginjuice_v400.sarif results/ 2>/dev/null || true
cp $DL/PRODUCTION_READINESS_v4.0.0.md results/
rm -f /tmp/sentinel-4.0.0-complete-bundle.zip
zip -q -r /tmp/sentinel-4.0.0-complete-bundle.zip .
cp /tmp/sentinel-4.0.0-complete-bundle.zip $DL/sentinel-4.0.0-complete-bundle.zip
unzip -l $DL/sentinel-4.0.0-complete-bundle.zip | tail -2

echo "== 3) rebuild the FULL ARCHIVE (all version sources + bundle + docs + gates + readiness) =="
rm -rf /tmp/full-arch && mkdir -p /tmp/full-arch/archives
cd /tmp/full-arch
# all historical source zips + current bundle
cp $DL/sentinel-*-source.zip archives/ 2>/dev/null || true
cp $DL/sentinel-4.0.0-complete-bundle.zip archives/ || true
# current tree + docs + readiness evidence
cp -r $Z sentinel-4.0.0-tree
mkdir -p readiness-evidence
cp $R/evidence/A01_FULL_FINAL_v3.json $R/evidence/A03_FINAL_v3.json $R/evidence/FINAL4_doctor.json \
   $R/evidence/G16_G17_verdict.json $R/evidence/Q_stress.json $R/evidence/U_memory.json \
   $R/evidence/Y_walkthrough.json $R/evidence/T_report_validation.json readiness-evidence/ 2>/dev/null || true
cp -r $R/results readiness-results
cp $DL/PRODUCTION_READINESS_v4.0.0.md .
rm -f /tmp/SENTINEL-FULL-ARCHIVE-v4.0.0.zip
zip -q -r /tmp/SENTINEL-FULL-ARCHIVE-v4.0.0.zip .
cp /tmp/SENTINEL-FULL-ARCHIVE-v4.0.0.zip $DL/SENTINEL-FULL-ARCHIVE-v4.0.0.zip
unzip -l $DL/SENTINEL-FULL-ARCHIVE-v4.0.0.zip | tail -2
echo "== packaging complete =="
ls -la $DL/*.zip $DL/PRODUCTION_READINESS_v4.0.0.md | awk '{print $5, $9}'
