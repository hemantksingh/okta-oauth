using System;
using System.Net;
using System.Reflection;
using System.Web.Helpers;
using System.Web.Mvc;

namespace Okta.OAuth.CodeFlow.Controllers
{
	public class HealthController : Controller
    {
        public ActionResult Index()
        {
			Version assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version;

			return Json(
				new {
					status = HttpStatusCode.OK,
					version = assemblyVersion.ToString()
				}, 
				JsonRequestBehavior.AllowGet);
		}
    }
}