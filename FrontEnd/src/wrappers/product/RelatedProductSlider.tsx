import PropTypes from "prop-types";
import React from "react";
import Swiper from "react-id-swiper";
import SectionTitle from "../../components/section-title/SectionTitle";
import ProductGrid from "./ProductGrid";

const RelatedProductSlider = ({ spaceBottomClass, category } : any) => {
    const settings = {
        loop: false,
        slidesPerView: 4,
        grabCursor: true,
        breakpoints: {
            1024: {
                slidesPerView: 4
            },
            768: {
                slidesPerView: 3
            },
            640: {
                slidesPerView: 2
            },
            320: {
                slidesPerView: 1
            }
        }
    };

    return (
        <div
            className={`related-product-area ${
                spaceBottomClass ? spaceBottomClass : ""
            }`}
        >
            <div className="container">
                <SectionTitle
                    titleText="Related Products"
                    positionClass="text-center"
                    spaceClass="mb-50"
                />
                <div className="row">
                    <Swiper {...settings}>
                        <ProductGrid
                            category={category}
                            limit={6}
                            sliderClassName="swiper-slide"
                        />
                    </Swiper>
                </div>
            </div>
        </div>
    );
};

RelatedProductSlider.propTypes = {
    category: PropTypes.string,
    spaceBottomClass: PropTypes.string
};

export default RelatedProductSlider;
