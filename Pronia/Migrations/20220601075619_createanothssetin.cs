using Microsoft.EntityFrameworkCore.Migrations;

namespace Pronia.Migrations
{
    public partial class createanothssetin : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_SocialMedia_Settings_SettingId",
                table: "SocialMedia");

            migrationBuilder.DropPrimaryKey(
                name: "PK_SocialMedia",
                table: "SocialMedia");

            migrationBuilder.RenameTable(
                name: "SocialMedia",
                newName: "SocialMedias");

            migrationBuilder.RenameIndex(
                name: "IX_SocialMedia_SettingId",
                table: "SocialMedias",
                newName: "IX_SocialMedias_SettingId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_SocialMedias",
                table: "SocialMedias",
                column: "Id");

            migrationBuilder.CreateTable(
                name: "AnotherSettings",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    HeaderLogo = table.Column<string>(nullable: true),
                    FooterLogo = table.Column<string>(nullable: true),
                    SearchIcon = table.Column<string>(nullable: true),
                    AccountIcon = table.Column<string>(nullable: true),
                    WishListIcon = table.Column<string>(nullable: true),
                    BasketIcon = table.Column<string>(nullable: true),
                    Phone = table.Column<string>(nullable: true),
                    AdvertisementImage = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnotherSettings", x => x.Id);
                });

            migrationBuilder.AddForeignKey(
                name: "FK_SocialMedias_Settings_SettingId",
                table: "SocialMedias",
                column: "SettingId",
                principalTable: "Settings",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_SocialMedias_Settings_SettingId",
                table: "SocialMedias");

            migrationBuilder.DropTable(
                name: "AnotherSettings");

            migrationBuilder.DropPrimaryKey(
                name: "PK_SocialMedias",
                table: "SocialMedias");

            migrationBuilder.RenameTable(
                name: "SocialMedias",
                newName: "SocialMedia");

            migrationBuilder.RenameIndex(
                name: "IX_SocialMedias_SettingId",
                table: "SocialMedia",
                newName: "IX_SocialMedia_SettingId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_SocialMedia",
                table: "SocialMedia",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_SocialMedia_Settings_SettingId",
                table: "SocialMedia",
                column: "SettingId",
                principalTable: "Settings",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
