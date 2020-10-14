#!/usr/bin/env python3

import sys
import json
import tempfile
import os.path
import subprocess

def slurp_json(filename):
    contents = None
    with open(filename) as f:
        contents = f.read()
    obj = json.loads(contents)
    return obj

def obj_to_dot(obj):
    ts = lambda x: f"\t{x};\n"
    q = lambda x: f"\"{x}\""

    dot = "digraph G {\n"
    edges = []
    for k,v in obj.items():
        dot += ts(q(k))

        for group in v:
            middle_ip = group["middle"]
            dot += ts(q(middle_ip))
            edges.append(ts(f"{q(k)} -> {q(middle_ip)}"))
            for edge in group["edges"]:
                dot += ts(q(edge))
                edges.append(ts(f"{q(middle_ip)} -> {q(edge)}"))
    dot += "\n"
    for edge in edges:
        dot += edge
    dot += "}\n"
    return dot

def obj_to_conflu(obj):
    conflu = "||Proxy|||Middle|||Edge||\n"
    for k,v in obj.items():
        for group in v:
            middle_ip = group["middle"]
            for edge in group["edges"]:
                conflu += f"|{k}|{middle_ip}|{edge}|\n"
    return conflu

def run_dot(dot, outputfilename):
    with tempfile.TemporaryDirectory() as tmpdirname:
        dotfilename = os.path.join(tmpdirname, "dot.dot")
        pngfilename = outputfilename
        with open(dotfilename, "w") as f:
            f.write(dot)
        args = ["dot", "-Tpng", "-o", pngfilename, dotfilename]
        subprocess.run(args, check=True)

def usage():
    sys.stderr.write(f"Usage: {sys.argv[0]} json_input.json\n")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()
    inputfilename = sys.argv[1]
    outputbasename = os.path.splitext(inputfilename)[0]
    png_output_filename =  outputbasename + ".png"
    conflu_output_filename = outputbasename + ".conflu"
    obj = slurp_json(inputfilename)
    dot = obj_to_dot(obj)
    run_dot(dot, png_output_filename)
    with open(conflu_output_filename, "w") as f:
        f.write(obj_to_conflu(obj))
    print(f"Wrote png graph as {png_output_filename}")
    print(f"Wrote confluence markup as {conflu_output_filename}")
    print()
    print("Have a nice day!")

if __name__ == "__main__":
    main()
