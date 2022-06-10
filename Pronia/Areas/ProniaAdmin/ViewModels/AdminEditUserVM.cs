using Pronia.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Areas.ProniaAdmin.ViewModels
{
    public class AdminEditUserVM
    {
        [Required, StringLength(maximumLength: 15)]
        public string FirstName { get; set; }

        [Required, StringLength(maximumLength: 20)]
        public string LastName { get; set; }
        [Required, StringLength(maximumLength: 15)]
        public string Username { get; set; }
        [Required, DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [DataType(DataType.Password)]
        public string CurrentPassword { get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password), Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
        public Roles Roles { get; set; }
    }
}
