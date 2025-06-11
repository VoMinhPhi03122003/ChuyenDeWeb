import PropTypes from "prop-types";
import React from "react";
import {Link} from "react-router-dom";

const SliderSingle = ({data, sliderClassName}: any) => {
    return (
        <div
            className={`single-slider slider-height-1 bg-purple ${
                sliderClassName ? sliderClassName : ""
            }`}
        >
            <div className="container">
                <div className="row">
                    <div className="col-xl-6 col-lg-6 col-md-6 col-12 col-sm-6 ">
                        <div className="slider-content slider-animated-1">
                            <h3 className="animated">{data.title}</h3>
                            <h1 className="animated">{data.subtitle}</h1>
                            <div className="slider-btn btn-hover">
                                <Link
                                    className="animated"
                                    to={"/shop"}
                                >
                                    MUA SẮM NGAY
                                </Link>
                            </div>
                        </div>
                    </div>
                    <div className="col-xl-6 col-lg-6 col-md-6 col-12 col-sm-6">
                        <div className="slider-single-img slider-animated-1">
                            <img
                                className="animated img-fluid "
                                style={{padding: "20px", maxHeight: "600px"}}
                                src={data.image}
                                alt=""
                            />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

SliderSingle.propTypes = {
    data: PropTypes.object,
    sliderClassName: PropTypes.string
};

export default SliderSingle;
