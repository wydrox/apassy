const $ = (id) => document.getElementById(id);
$("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const r = await fetch("/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: $("username").value, password: $("password").value }) });
  const data = await r.json();
  $("status").dataset.state = data.ok ? "ok" : "error";
  $("status").textContent = data.ok ? "Signed in: the filled password matches." : `Refused (${data.error ?? "password does not match"}).`;
});
