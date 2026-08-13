from backend.app.scanners.engine import generate_bucket_names


def test_company_candidates_survive_small_scan_limit():
    names = generate_bucket_names(
        keywords=["backup"],
        companies=["Acme Corp"],
        max_names=10,
    )

    assert len(names) == 10
    assert names["acme-corp"] == "Acme Corp"
    assert all(company == "Acme Corp" for company in names.values())


def test_generic_candidates_are_not_attributed():
    names = generate_bucket_names(keywords=["backup"], max_names=10)

    assert len(names) == 10
    assert all(company == "" for company in names.values())
