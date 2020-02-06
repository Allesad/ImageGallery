using Microsoft.AspNetCore.Mvc;

namespace ImageGallery.Client.Controllers
{
    public class AuthorizationController : Controller
    {
        public IActionResult AccessDenied() => View();
    }
}
