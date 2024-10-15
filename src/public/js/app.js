window.onload = function () {
  handleGoBack();
};

function handleGoBack() {
  document.querySelectorAll(".go-back").forEach((goBack) => {
    goBack.addEventListener("click", function () {
      window.history.back();
    });
  });
}
