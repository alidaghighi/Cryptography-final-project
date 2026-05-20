$pdf_mode = 5;          # XeLaTeX
$postscript_mode = 0;
$dvi_mode = 0;
$bibtex_use = 2;        # biber
$out_dir = '_latexmk';

# Write final PDF beside the .tex file
$compiling_cmd = '';

add_cus_dep('bcf', 'bbl', 0, 'run_biber');
sub run_biber {
    return system("biber --input-directory=$out_dir --output-directory=$out_dir $_[0]");
}
