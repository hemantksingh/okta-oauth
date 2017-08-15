using System;
using System.Net;
using System.Reflection;
using System.Web.Http;

namespace Okta.OAuth.Api
{
	[Route("health")]
	public class HealthController : ApiController
	{
		public IHttpActionResult Get()
		{
			Version assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version;
			
			return Json( new
				{
					status = HttpStatusCode.OK,
					version = assemblyVersion.ToString()
				});
		}
	}
}