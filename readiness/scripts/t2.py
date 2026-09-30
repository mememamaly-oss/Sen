import json
d=json.JSONDecoder().raw_decode(open("/home/z/my-project/readiness/evidence/A03_bench_zip_1.json").read())
print("parsed f1:",d[0]["f1"])
