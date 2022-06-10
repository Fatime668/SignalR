using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Extensions
{
    public static class FileExtention
    {
        //public static bool IsImage(this IFormFile file)
        //{
        //    return file.ContentType.Contains("image");
        //}
        //public static bool IsGreater(this IFormFile file, int mb)
        //{
        //    return file.Length < mb * 1024 * 1024;
        //}
        public static bool IsOkay(this IFormFile file, int mb)
        {
            return file.ContentType.Contains("image") && file.Length < mb * 1024 * 1024;
        }
    }
}
