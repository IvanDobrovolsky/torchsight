class Torchsight < Formula
  desc "Open-source security scanner and document classifier powered by local LLMs"
  homepage "https://github.com/IvanDobrovolsky/torchsight"
  license "Apache-2.0"

  # Updated by release workflow
  url "https://github.com/IvanDobrovolsky/torchsight/archive/refs/tags/v0.1.0.tar.gz"
  sha256 ""

  depends_on "rust" => :build
  depends_on "ollama"
  depends_on "tesseract"
  depends_on "poppler" # for pdftotext

  def install
    system "cargo", "build", "--release"
    bin.install "target/release/torchsight"
  end

  def post_install
    ohai "Pulling TorchSight Beam model (this may take a while)..."
    system "ollama", "pull", "torchsight/beam"
  end

  test do
    assert_match "torchsight", shell_output("#{bin}/torchsight --version")
  end
end
