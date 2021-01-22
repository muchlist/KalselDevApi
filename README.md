# KalselDevApi

Source code rest-api pada situs kalselDev.  
Dokumentasi lengkap penggunaan api silahkan kunjungi [KalselDevDoc](https://kalsel.dev)


## Menjalankan program di mesin sendiri

1. Clone repo ini
2. Buat file `.env` di root folder, silahkan mengacu kepada file `.env.example`
3. Unduh semua dependency, bisa menggunakan perintah `go mod download` atau `go mod tidy` sekalian bersih bersih
4. Jalankan dengan `go run main.go`

## Dependency lokal

- [ErruUtils](https://github.com/muchlist/erru_utils_go)  
Library ini digunakan untuk memformat response error dan logger sehingga response error memiliki format yang standart di setiap service (berguna jika akan mengimplementasikan microservice).

## Dependency pihak ketiga

- [Go Fiber Framework](https://github.com/gofiber/fiber/v2) : Web framework golang yang memiliki kemiripan dengan express js dan menggunakan fast-http (tidak berbeda jauh dengan gin dan echo).
- [Mongo go driver](https://go.mongodb.org/mongo-driver) : Saat ini service ini full menggunakan MongoDB. 
- [JWT go](https://github.com/dgrijalva/jwt-go)
- [Ozzo validation](github.com/go-ozzo/ozzo-validation/v4) : Library yang digunakan untuk validasi request body dari user. (Karena Go Fiber tidak memiliki input validasi seperti Binding di Gin)

# Kontribusi

Kontribusi bisa dalam bentuk apapun, memperbaiki codingan, share code yang mengimplementasikan api, membuat gambar illustrasi, menambah fungsi, menambah dan memperbaiki dokumentasi, memberikan resource server, menyumbangkan ide dsb.
Author masih baru dalam hal open sourse silahkan sampaikan apapun yang mengganggu sodara.

# Kontributor
-
