-- Giris deneme sinirlamasi.
--
-- Sayac ve kilit veritabaninda tutulur; bellekte tutulsaydi servis her
-- yeniden basladiginda sifirlanir ve sinir islevsiz kalirdi.
ALTER TABLE users
    ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN locked_until    TIMESTAMPTZ;
