const q = req.query.q;
eval(q);
document.getElementById("out").innerHTML = q;
