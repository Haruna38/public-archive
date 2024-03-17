const fs = require("fs").promises;

const readFile = async function (fName) {
	return (await fs.readFile(fName, "utf-8")).trim();
}

const writeFile = async function (fDest, content) {
	return await fs.writeFile(fDest, content);
}

const cleanSplit = function (str, delim) {
	return str.split(delim).map(e => e.trim()).filter(e => e);
}

const parser = async function () {
	let norm = await readFile("./VB.NET.txt"), ext = await readFile("./VB.NET-extension.txt");

	let statements = cleanSplit(norm + "\n\n" + ext, "\n\n");

	let syntax = [];

	for (let e of statements) {
		let [definition, expr] = cleanSplit(e, "::=");
		let lines = cleanSplit(expr, /\n+/);

		for (let j = 0; j < lines.length; ++j) {
			let line = lines[j];
			let parts = line.match(/("|')((?:\\\1|(?:(?!\1).))*)\1|\w+|[^\s\w]+/g);
			for (let i = 0; i < parts.length; ++i) {
				let part = parts[i].trim();
				if (
					(part.startsWith('"') && part.endsWith('"')) ||
					(part.startsWith("'") && part.endsWith("'"))
					)
					parts[i] = part;
				else if (part.match(/^\w+$/)) parts[i] = `<${part}>`;
				else parts[i] = part.split("").join(" ");
			}
			lines[j] = parts.join(" ");
		}

		syntax.push({ definition, lines });
	}

	let max_expr_len = Math.max(...syntax.map(a => a.definition.length)) + 3, sep = "\n" + " ".repeat(max_expr_len) + "|" + "   ";

	await writeFile("./VB.NET-complete.txt", syntax.map(a => `<${a.definition}>${" ".repeat(max_expr_len - a.definition.length - 3)} ::= ${a.lines.join(sep)}`).join("\n\n"));
}

parser().then(e => console.log("Write successfully")).catch(console.error);