const $ = (id) => document.getElementById(id);
$("otp").addEventListener("submit", async (event) => {
  event.preventDefault();
  const r = await fetch("/api/otp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: $("code").value }) });
  const data = await r.json();
  $("status").dataset.state = data.ok ? "ok" : "error";
  $("status").textContent = data.ok ? "Verified: the filled code matches." : `Refused (${data.error ?? "code does not match"}).`;
});
