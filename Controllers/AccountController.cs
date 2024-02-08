using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using IdentityManager.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Exchange.WebServices.Data;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signManager)
        {
            _userManager = userManager;
            _signManager = signManager;
        }


        public IActionResult Register(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            RegisterViewModel model = new();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Name
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    var callbackurl = Url.Action("ConfirmEmail", "Account",
                        new { userid = user.Id, code }, protocol: HttpContext.Request.Scheme);

                    EmailSender servicoEmail = new EmailSender();
                    servicoEmail.SendEmail(model.Email, "Confirm Email - Identity",
                                                        $"Please confirm your email by clicking here: <a href='{callbackurl}'>link </a>");

                    await _signManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                }
               AddErrors(result);
            }

            return View(model);


           
        }

        public IActionResult Login(string returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            LoginViewModel model = new();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model, string returnurl = null)
        {

            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                var result = await _signManager.PasswordSignInAsync(model.Email, model.Password,model.RememberMe, lockoutOnFailure:true);

                if (result.Succeeded)
                {
                    return LocalRedirect(returnurl);
                }

                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { model.RememberMe, returnurl });
                        
                }


                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View(model);
                }
            }
            return View(model);
        }


        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signManager.GetTwoFactorAuthenticationUserAsync();

            if(user == null)
            {
                return View("Error");
            }

            ViewData["ReturnUrl"] = returnUrl;

            return View(new VerifyAuthenticatorViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe, });
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string code, string userId)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    return View("Error");
                }

                var result = await _userManager.ConfirmEmailAsync(user, code);

                if (result.Succeeded)
                {
                    return View();
                }
                
            }


            return View("Error");
        }

        [HttpGet]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Error()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", 
                        new {userid = user.Id, code }, protocol: HttpContext.Request.Scheme);
            
                EmailSender servicoEmail = new EmailSender();
                servicoEmail.SendEmail(model.Email, "Reset Password - Identity",
                                                    $"Please reset your password by clicking here: <a href='{callbackurl}'>link </a>");

                return RedirectToAction(nameof(ForgotPasswordConfirmation));

            }
            

            return View(model);
        }

        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if(user == null)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }

                var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                AddErrors(result);
            }


            return View(model);
        }



        [HttpGet]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }




        [HttpGet]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var model = new TwoFactorAuthenticationViewModel() { Token = token };

            return View(model);

        }


        [HttpGet]
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticatior(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);


                var tokenProvider = _userManager.Options.Tokens.AuthenticatorTokenProvider;

                var result = await _userManager.VerifyTwoFactorTokenAsync(user, tokenProvider,model.Code);

                if (result) 
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor auth code cold not be validated.");
                    return View(model);
                }



                return RedirectToAction(nameof(AuthenticatorConfirmation));
            }

            return View("Error");

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var erro in result.Errors)
            {
                ModelState.AddModelError(string.Empty, erro.Description);
            }
        }
    }
}
