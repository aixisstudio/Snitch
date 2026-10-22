# Snitch — Homebrew formula template (rendered by release.yml →
# aixisstudio/homebrew-tap). @VERSION@/@SHA256@ are CI placeholders.
# FR: Modèle de formule Homebrew (rendu par release.yml vers le tap).
class Snitch < Formula
  desc "Local-first network observability and outbound firewall"
  homepage "https://github.com/aixisstudio/Snitch"
  url "https://github.com/aixisstudio/Snitch/archive/refs/tags/v@VERSION@.tar.gz"
  sha256 "@SHA256@"
  license "AGPL-3.0-or-later"
  head "https://github.com/aixisstudio/Snitch.git", branch: "main"

  depends_on "python@3.13"

  def install
    venv = virtualenv_create(libexec, "python3.13")
    venv.pip_install resources
    # EN: the backend is the product — install the tree, link a launcher.
    # FR: le backend est le produit — installer l'arbre, lier un lanceur.
    libexec.install "backend"
    (bin/"snitch").write_env_script libexec/"bin/python",
      "-m uvicorn api.main:app --host 127.0.0.1 --port 8000",
      PYTHONPATH: libexec/"backend", SNITCH_DATA_DIR: var/"snitch"
  end

  service do
    run [opt_bin/"snitch"]
    keep_alive true
    log_path var/"log/snitch.log"
    error_log_path var/"log/snitch.log"
  end

  test do
    system bin/"snitch", "--help"
  end
end
