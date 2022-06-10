using Microsoft.EntityFrameworkCore.Migrations;

namespace Pronia.Migrations
{
    public partial class createColmn : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "AnotherSettingId",
                table: "SocialMedias",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_SocialMedias_AnotherSettingId",
                table: "SocialMedias",
                column: "AnotherSettingId");

            migrationBuilder.AddForeignKey(
                name: "FK_SocialMedias_AnotherSettings_AnotherSettingId",
                table: "SocialMedias",
                column: "AnotherSettingId",
                principalTable: "AnotherSettings",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_SocialMedias_AnotherSettings_AnotherSettingId",
                table: "SocialMedias");

            migrationBuilder.DropIndex(
                name: "IX_SocialMedias_AnotherSettingId",
                table: "SocialMedias");

            migrationBuilder.DropColumn(
                name: "AnotherSettingId",
                table: "SocialMedias");
        }
    }
}
