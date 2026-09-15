import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.html_parse import extract_anchor_links, href_path_matches, link_text_matches, normalize_text


class TestNormalizeText(unittest.TestCase):
    def test_strips_accents_and_lowercases(self):
        self.assertEqual(normalize_text("Mentions Légales"), "mentions legales")
        self.assertEqual(normalize_text("Données Personnelles"), "donnees personnelles")

    def test_already_normalized_is_unchanged(self):
        self.assertEqual(normalize_text("legal notice"), "legal notice")


class TestExtractAnchorLinks(unittest.TestCase):
    def test_extracts_simple_link(self):
        html = '<a href="/mentions-legales">Mentions légales</a>'
        links = extract_anchor_links(html)
        self.assertEqual(links, [("/mentions-legales", "Mentions légales")])

    def test_extracts_link_with_nested_tags_in_text(self):
        """Cas réaliste : le texte visible est dans un <span> imbriqué."""
        html = '<a href="/mentions-legales"><span>Mentions</span> <span>légales</span></a>'
        links = extract_anchor_links(html)
        self.assertEqual(links[0][0], "/mentions-legales")
        self.assertIn("Mentions", links[0][1])
        self.assertIn("légales", links[0][1])

    def test_extracts_multiple_links(self):
        html = """
        <footer>
            <a href="/mentions-legales">Mentions légales</a>
            <a href="/politique-de-confidentialite">Politique de confidentialité</a>
        </footer>
        """
        links = extract_anchor_links(html)
        self.assertEqual(len(links), 2)

    def test_link_without_href_returns_empty_href(self):
        html = '<a>Sans lien</a>'
        links = extract_anchor_links(html)
        self.assertEqual(links[0][0], "")

    def test_no_links_returns_empty_list(self):
        self.assertEqual(extract_anchor_links("<div>Rien ici</div>"), [])


class TestHrefPathMatches(unittest.TestCase):
    """Scénario mission : URL évidente."""

    def test_relative_href_matches(self):
        self.assertTrue(href_path_matches("/mentions-legales", ("mentions-legales",)))

    def test_absolute_href_matches(self):
        self.assertTrue(
            href_path_matches("https://www.castorama.fr/mentions-legales", ("mentions-legales",))
        )

    def test_href_with_query_params_matches(self):
        """Scénario mission : URL avec paramètres."""
        self.assertTrue(
            href_path_matches("/mentions-legales?ref=footer&lang=fr", ("mentions-legales",))
        )

    def test_href_with_fragment_matches(self):
        self.assertTrue(href_path_matches("/mentions-legales#section-2", ("mentions-legales",)))

    def test_underscore_variant_matches_hyphen_keyword(self):
        self.assertTrue(href_path_matches("/mentions_legales", ("mentions-legales",)))

    def test_accented_path_matches_unaccented_keyword(self):
        self.assertTrue(href_path_matches("/politique-de-confidentialité", ("confidentialite",)))

    def test_unrelated_href_does_not_match(self):
        self.assertFalse(href_path_matches("/promotions/french-days", ("mentions-legales", "confidentialite")))

    def test_anchor_only_href_does_not_match(self):
        self.assertFalse(href_path_matches("#top", ("mentions-legales",)))

    def test_mailto_does_not_match(self):
        self.assertFalse(href_path_matches("mailto:contact@example.com", ("mentions-legales",)))

    def test_empty_href_does_not_match(self):
        self.assertFalse(href_path_matches("", ("mentions-legales",)))


class TestLinkTextMatches(unittest.TestCase):
    def test_exact_french_text_matches(self):
        self.assertTrue(link_text_matches("Mentions légales", ("mentions légales",)))

    def test_case_insensitive(self):
        self.assertTrue(link_text_matches("MENTIONS LÉGALES", ("mentions légales",)))

    def test_atypical_url_recognizable_text_matches(self):
        """Scénario mission : lien dont le texte indique 'Mentions légales'
        mais dont l'URL est atypique (ex: /page-42.html, /info-societe)."""
        self.assertTrue(link_text_matches("Mentions légales", ("mentions légales",)))
        # Le href n'a pas besoin de matcher : le texte suffit.

    def test_english_variant_matches(self):
        """Scénario mission : variante anglaise."""
        self.assertTrue(link_text_matches("Legal Notice", ("legal notice",)))
        self.assertTrue(link_text_matches("Privacy Policy", ("privacy policy",)))

    def test_data_personal_variant_matches(self):
        self.assertTrue(link_text_matches("Données personnelles", ("données personnelles",)))

    def test_unrelated_text_does_not_match(self):
        self.assertFalse(link_text_matches("Nos promotions", ("mentions légales", "confidentialité")))

    def test_empty_text_does_not_match(self):
        self.assertFalse(link_text_matches("", ("mentions légales",)))


class TestRealisticFooterScenario(unittest.TestCase):
    """Scénario mission : page légale accessible uniquement via un lien du
    footer (pas de chemin conventionnel deviné correctement)."""

    def test_footer_link_with_atypical_path_is_found_via_text(self):
        html = """
        <html><body>
        <main>beaucoup de contenu produit ici...</main>
        <footer>
            <a href="/page-info-42.html">Mentions légales</a>
            <a href="/rgpd-details">Politique de protection des données</a>
        </footer>
        </body></html>
        """
        links = extract_anchor_links(html)
        legal_notice_found = any(
            href_path_matches(h, ("mentions-legales", "legal-notice"))
            or link_text_matches(t, ("mentions légales", "legal notice", "informations légales"))
            for h, t in links
        )
        privacy_found = any(
            href_path_matches(h, ("confidentialite", "privacy-policy"))
            or link_text_matches(t, ("politique de confidentialité", "protection des données", "données personnelles"))
            for h, t in links
        )
        self.assertTrue(legal_notice_found)
        self.assertTrue(privacy_found)

    def test_genuine_absence_finds_nothing(self):
        """Scénario mission : absence réelle de page légale."""
        html = """
        <html><body>
        <footer>
            <a href="/promotions">Nos promotions</a>
            <a href="/contact">Nous contacter</a>
        </footer>
        </body></html>
        """
        links = extract_anchor_links(html)
        found = any(
            href_path_matches(h, ("mentions-legales", "legal-notice"))
            or link_text_matches(t, ("mentions légales", "legal notice"))
            for h, t in links
        )
        self.assertFalse(found)


if __name__ == "__main__":
    unittest.main()
