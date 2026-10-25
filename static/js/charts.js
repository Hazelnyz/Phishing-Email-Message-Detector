/* Local, dependency-free interactive charts. All plotted values come from /api/metrics. */
document.addEventListener("DOMContentLoaded", async function () {
  var chart = document.getElementById("metricChart");
  if (!chart) return;
  var response = await fetch("/api/metrics", { headers: { Accept: "application/json" } });
  if (!response.ok) return;
  var metrics = await response.json();
  var select = document.getElementById("chartTestSet");
  var legend = document.getElementById("chartLegend");
  var colors = ["#102a43", "#078184", "#a76a12"];
  var names = ["Precision", "Recall", "F1"];
  legend.innerHTML = names.map(function (name, i) {
    return '<span><i style="--legend-color:' + colors[i] + '"></i>' + name + '</span>';
  }).join("");

  function drawBars() {
    var ctx = chart.getContext("2d");
    var rect = chart.getBoundingClientRect();
    var ratio = window.devicePixelRatio || 1;
    chart.width = Math.max(320, rect.width * ratio);
    chart.height = 300 * ratio;
    ctx.scale(ratio, ratio);
    var width = chart.width / ratio, height = chart.height / ratio;
    ctx.clearRect(0, 0, width, height);
    var models = metrics.test_sets[select.value];
    var modelNames = Object.keys(models);
    var left = 42, top = 18, plotHeight = height - 60, plotWidth = width - 58;
    ctx.font = "12px system-ui"; ctx.fillStyle = "#526274"; ctx.strokeStyle = "#d5dee5";
    [0, .25, .5, .75, 1].forEach(function (tick) {
      var y = top + plotHeight * (1 - tick);
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - 12, y); ctx.stroke();
      ctx.fillText(tick.toFixed(2), 2, y + 4);
    });
    var groupWidth = plotWidth / modelNames.length, barWidth = Math.min(32, groupWidth / 5);
    modelNames.forEach(function (model, mi) {
      var center = left + groupWidth * (mi + .5);
      ["precision", "recall", "f1"].forEach(function (key, i) {
        var value = models[model][key], x = center + (i - 1) * (barWidth + 5) - barWidth / 2;
        var barHeight = value * plotHeight;
        ctx.fillStyle = colors[i]; ctx.fillRect(x, top + plotHeight - barHeight, barWidth, barHeight);
        ctx.fillStyle = "#526274"; ctx.textAlign = "center";
        ctx.fillText(value.toFixed(2), x + barWidth / 2, top + plotHeight - barHeight - 5);
      });
      ctx.fillStyle = "#172638"; ctx.textAlign = "center";
      ctx.fillText(model, center, height - 12);
    });
  }

  function drawHeatmaps() {
    var holder = document.getElementById("confusionCharts");
    holder.replaceChildren();
    Object.entries(metrics.test_sets[select.value]).forEach(function (entry) {
      var model = entry[0], values = entry[1].confusion_matrix;
      var figure = document.createElement("figure");
      var caption = document.createElement("figcaption");
      caption.textContent = model + " — confusion matrix";
      var canvas = document.createElement("canvas");
      canvas.width = 280; canvas.height = 200;
      canvas.setAttribute("aria-hidden", "true");
      figure.append(caption, canvas); holder.appendChild(figure);
      var ctx = canvas.getContext("2d"), max = Math.max.apply(null, values.flat()) || 1;
      ["Legitimate", "Phishing"].forEach(function (row, i) {
        ["Legitimate", "Phishing"].forEach(function (col, j) {
          var x = 96 + j * 88, y = 40 + i * 66, value = values[i][j];
          var alpha = .12 + .72 * value / max;
          ctx.fillStyle = "rgba(7,129,132," + alpha + ")";
          ctx.fillRect(x, y, 76, 54);
          ctx.fillStyle = value / max > .48 ? "#ffffff" : "#172638";
          ctx.textAlign = "center"; ctx.font = "bold 17px system-ui";
          ctx.fillText(String(value), x + 38, y + 31);
        });
      });
      ctx.fillStyle = "#526274"; ctx.font = "11px system-ui"; ctx.textAlign = "center";
      ctx.fillText("Predicted legitimate", 134, 28); ctx.fillText("Predicted phishing", 222, 28);
      ctx.textAlign = "right"; ctx.fillText("Actual legitimate", 90, 70); ctx.fillText("Actual phishing", 90, 136);
    });
  }
  select.addEventListener("change", function () { drawBars(); drawHeatmaps(); });
  window.addEventListener("resize", drawBars);
  drawBars(); drawHeatmaps();
});
